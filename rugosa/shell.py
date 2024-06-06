"""
Shell tool for interacting with emulation.
"""
import argparse
import collections
import contextlib
import difflib
import functools
import os
import reprlib
import logging

import re
import shutil
import sys
import tempfile
import threading
from pathlib import Path
from typing import Union, Optional, Iterable

from cmd2 import Statement
from hexdump import hexdump

from rugosa.emulation.cpu_context import ProcessorContext
from rugosa import __version__
import rugosa.re

import cmd2
import dragodis
from dragodis import Disassembler
from tabulate import tabulate, tabulate_formats

from rugosa import Emulator, func_utils


MISSING = object()

LOGO = """\
 ____                              
|  _ \ _   _  __ _  ___  ___  __ _ 
| |_) | | | |/ _` |/ _ \/ __|/ _` |
|  _ <| |_| | (_| | (_) \__ \ (_| |
|_| \_\\\\__,_|\__, |\___/|___/\__,_|
             |___/                  """


CATEGORY_EMULATION_CONTROL = "Emulation Control"
CATEGORY_EMULATION_INFO = "Emulation Info"
CATEGORY_EMULATION_ARTIFACTS = "Emulation Artifacts"
CATEGORY_DISASSEMBLY = "Disassembly"

fg_colors = [c.name.lower() for c in cmd2.Fg]

auto_int = functools.partial(int, base=0)

custom_repr = reprlib.Repr()
custom_repr.maxother = 50
trepr = custom_repr.repr


class Cmd2FeedbackHandler(logging.Handler):

    def __init__(self, app: cmd2.Cmd):
        super().__init__()
        self._app = app

    def emit(self, record):
        self._app.pfeedback(self.format(record))


class App(cmd2.Cmd):
    """Rugosa Interactive Shell"""

    def __init__(self, dis: Disassembler, logo=True, history_file: str = None, startup_script: str = None, precache=True):
        super().__init__(
            include_py=True,
            include_ipy=True,
            persistent_history_file=history_file,
            startup_script=startup_script,
        )
        self._ctx_history = collections.deque(maxlen=20)

        # Settings
        self.self_in_py = True
        self.default_category = "Shell Control"
        self.tablefmt = "simple"
        self.add_settable(cmd2.Settable("tablefmt", str, "Format for tables", self, choices=tabulate_formats))
        self.display_instruction = False
        self.add_settable(cmd2.Settable("display_instruction", bool, "Display current instruction in prompt", self))
        self.display_spdiff = False
        self.add_settable(cmd2.Settable("display_spdiff", bool, "Display the stack pointer diff in prompt", self))
        self.prompt_color = "green"
        self.add_settable(cmd2.Settable("prompt_color", str, "Color of prompt. 'reset' disables color", self, choices=fg_colors))
        self.add_settable(cmd2.Settable(
            "max_undo_items", int,
            "Maximum number of undo items to keep. Set to 0 to turn off undo.", self,
        ))
        self.log = False
        self.add_settable(cmd2.Settable("log", bool, "Display debug logs", self, onchange_cb=self.logs_cb))
        self._handler = None

        # Aliases
        self.aliases.update({
            "exit": "quit",
            "g": "goto",
            "c": "continue",
            "n": "next",
            "i": "info",
            "what": "info",
            "alt": "alternative",
            "insn": "instruction",
            "dis": "disassembly",
            "reg": "registers",
            "regs": "registers",
            "var": "variables",
            "vars": "variables",
            "arg": "arguments",
            "args": "arguments",
            "param": "parameters",
            "params": "parameters",
            "func": "functions",
            "funcs": "functions",
            "function": "functions",
            "op": "operands",
            "ops": "operands",
            "mem": "memory",
            "seg": "segments",
            "ref": "references",
            "refs": "references",
            "ehist": "exec_history",
            "bhist": "branch_history",
            "chist": "call_history",
        })

        self.dis = dis
        self.emu: Emulator
        self.ctx: ProcessorContext
        self._ctx_gen = None
        self._precache = precache
        self._function_names = []
        self._import_names = []
        self._threads = []
        self._reset(init=True)

        if logo:
            self.intro = (
                f"{LOGO}v{__version__}\n\n"
                f"Department of Defense Cyber Crime Center (DC3)\n\n"
                f"{self._get_status()}"
            )

    def _collect_function_names(self):
        self._function_names = [func.name for func in self.dis.functions()]

    def _cache_function_names(self):
        # Start thread to collect function names while idle for the tab completion.
        thread = threading.Thread(target=self._collect_function_names)
        thread.start()
        self._threads.append(thread)

    def _collect_import_names(self):
        self._import_names = [imp.name for imp in self.dis.imports]

    def _cache_import_names(self):
        # Start thread to collect import names while idle for the tab completion.
        thread = threading.Thread(target=self._collect_import_names)
        thread.start()
        self._threads.append(thread)

    def enable_logs(self):
        if not self._handler:
            logger = logging.root
            logger.setLevel(logging.DEBUG)
            handler = Cmd2FeedbackHandler(self)
            formatter = logging.Formatter("[%(levelname)s][%(name)s]\t\t%(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            self._handler = handler
            # For IDA, we have to set the remote logger too.
            if hasattr(self.dis, "_bridge"):
                remote_logger = self.dis._bridge.modules.logging.getLogger()
                remote_logger.setLevel(logging.DEBUG)

    def disable_logs(self):
        if self._handler:
            logger = logging.root
            logger.removeHandler(self._handler)
            self._handler = None

    def logs_cb(self, name, orig_value, new_value):
        """Callback for when the 'logs' setting is enabled/disabled."""
        if new_value and not orig_value:
            self.enable_logs()
        else:
            self.disable_logs()

    def postloop(self):
        # Ensure we allow any caching threads to complete before exiting.
        for thread in self._threads:
            thread.join()

    @property
    def max_undo_items(self) -> int:
        return self._ctx_history.maxlen

    @max_undo_items.setter
    def max_undo_items(self, value: int):
        self._ctx_history = collections.deque(self._ctx_history, maxlen=value)

    def _run_python(self, *, pyscript: Optional[str] = None) -> Optional[bool]:
        # Right before running python, set locals to include ctx, dis, and emu
        self.py_locals = {"ctx": self.ctx, "dis": self.dis, "emu": self.emu}
        return super()._run_python(pyscript=pyscript)

    def postcmd(self, stop: bool, statement: Union[Statement, str]) -> bool:
        self._set_prompt()
        return stop

    def _set_prompt(self):
        prompt = f"(0x{self.ctx.ip:08x}"
        if self.display_spdiff:
            prompt += f" {hex(self.ctx.sp_diff)}"
        if self.display_instruction:
            prompt += f": {self.ctx.instruction.text}"
        prompt += ")> "
        if self.prompt_color == "off":
            self.prompt = prompt
        else:
            self.prompt = cmd2.style(prompt, fg=cmd2.Fg[self.prompt_color.upper()])

    def _setup_emulator_settings(self, init=False):
        if not init:
            # remove settings from old instance if not initial.
            self.remove_settable("max_instructions")
            self.remove_settable("branch_tracking")

        self.add_settable(cmd2.Settable(
            "max_instructions", int,
            "Maximum number of instructions to allow when emulating loop following code. "
            "This is used since it is possible that the end instruction would never get reached.",
            self.emu,
        ))
        self.add_settable(cmd2.Settable(
            "branch_tracking", bool,
            "When forcing emulation to go down the incorrect branch in order to reach the desired "
            "end address, branch_tracking is used to try to tweak the registers to make the branching "
            "condition true. This can be helpful to ensure the rest of the emulation is done correctly, however "
            "this will cause emulation to run slower. "
            "So this option allows you to turn it off when the feature is not necessary.",
            self.emu
        ))

    def _reset(self, init=False):
        self.emu = Emulator(self.dis)
        self._setup_emulator_settings(init=init)
        if self.dis.entry_point:
            self.ctx = self.emu.context_at(self.dis.entry_point)
        else:
            self.ctx = self.emu.new_context()
        self._ctx_gen = None
        if not init:
            self._ctx_history.clear()
        self._save_ctx()
        self._set_prompt()
        if self._precache:
            self._cache_function_names()
            self._cache_import_names()

    def _save_ctx(self):
        # TODO: Save full context including emulator and path generator.
        #   Possibly allow user to save and reload sessions.
        if self._ctx_history.maxlen > 0:
            self._ctx_history.append(self.ctx.copy())

    def _obtain_address(self, target: str, default=MISSING) -> Optional[int]:
        """
        Obtains the address from a given user string using a best guess of what they wanted.
        """
        try:
            return auto_int(target)
        except ValueError:
            pass

        if target == ".":
            return self.ctx.ip

        if target == "sp":
            return self.ctx.sp

        if target.startswith("op") and target in {f"op{i}" for i in range(len(self.ctx.operands))}:
            operand = self.ctx.operands[int(target[2:])]
            return operand.addr or operand.value

        if re.fullmatch("arg\d+", target):
            ordinal = int(target[3:])
            try:
                args = self.ctx.function_args
                return args[ordinal].value
            except (dragodis.NotExistError, KeyError):
                pass

        if target in self.ctx.registers.names:
            return self.ctx.registers[target]

        if target in self.ctx.variables.names:
            return self.ctx.variables[target].addr

        if func := self.dis.get_function_by_name(target, default=None):
            return func.start

        if imp := self.dis.get_import(target, None):
            return imp.address

        if default is MISSING:
            # TODO: Add support for get_name_ea() in dragodis.
            self.perror(f"Invalid target: {target}")
            raise cmd2.Cmd2ArgparseError()
        else:
            return default

    def target_complete(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Completer for target variables."""
        if text == "0x":
            return []

        if not self._precache:
            self._cache_function_names()
            self._cache_import_names()
            self._precache = True

        match_against = [
            ".", "sp",
            *self.ctx.registers.names,
            *self.ctx.variables.names,
            *self._function_names,
            *self._import_names
        ]

        if text in ("o", "op"):
            match_against.extend(f"op{i}" for i in range(len(self.ctx.operands)))

        if text in ("a", "ar", "arg"):
            try:
                match_against.extend(f"arg{i}" for i in range(len(self.ctx.function_args)))
            except (dragodis.NotExistError, KeyError):
                pass

        return self.basic_complete(text, line, begidx, endidx, match_against)

    def ptable(self, tabular_data, headers="keys"):
        self.poutput(tabulate(tabular_data, headers=headers, tablefmt=self.tablefmt))

    def phexdump(self, data: bytes, start_address: int = 0):
        """Generates hexdump of data with given starting address."""
        lines = []
        for line in hexdump(data, result="generator"):
            addr, _, rest = line.partition(":")
            addr = int(addr, 16) + start_address
            line = f"{addr:08X}: {rest}"
            lines.append(line)
        self.poutput("\n".join(lines))

    def _get_status(self) -> str:
        return tabulate([
            ["File", self.dis.input_path],
            ["Disassembler", self.dis.name],
            ["Processor", self.dis.processor_name],
            ["Compiler", self.dis.compiler_name],
            ["Bit size", self.dis.bit_size],
            ["Endianness", "BE" if self.dis.is_big_endian else "LE"],
            ["Entry Point", f"0x{self.dis.entry_point:08x}" if self.dis.entry_point else ""],
        ], headers=(), tablefmt=self.tablefmt)

    @cmd2.with_category(CATEGORY_DISASSEMBLY)
    def do_status(self, args):
        """Prints out status information."""
        self.poutput(self._get_status())

    @cmd2.with_category(CATEGORY_EMULATION_CONTROL)
    def do_reset(self, args):
        """Resets the emulator and context."""
        self._reset()

    goto_parser = cmd2.Cmd2ArgumentParser()
    goto_parser.add_argument(
        "target",
        nargs="?",
        help="address or register/variable name for instruction address. "
             "(Defaults to going to current location. Useful for re-emulation with different settings.)",
        completer=target_complete,
    )
    goto_parser.add_argument(
        "-k", "--keep",
        action="store_true",
        help="Whether to create a context using current context. By default a new context is used."
    )
    goto_parser.add_argument(
        "-d", "--depth",
        action="store",
        type=int,
        default=0,
        help="Number of calls up the stack to emulate first."
    )
    goto_parser.add_argument(
        "-c", "--call-depth",
        action="store",
        type=int,
        default=0,
        help="Number of function calls we are allowed to emulate into."
    )
    goto_parser.add_argument(
        "-f", "--follow-loops",
        action="store_true",
        help="If set, loops will be followed during emulation and only one possible path will be emulated per call level."
    )

    def _next_ctx(self):
        if not self._ctx_gen:
            self.perror("Context generator not setup. Please run 'goto' command first.")
            raise cmd2.Cmd2ArgparseError()
        try:
            return next(self._ctx_gen)
        except StopIteration:
            self.perror("No more alternative paths exist.")
            raise cmd2.Cmd2ArgparseError()

    @cmd2.with_category(CATEGORY_EMULATION_CONTROL)
    @cmd2.with_argparser(goto_parser)
    def do_goto(self, args):
        """
        Sets execution context at provided address.
        """
        if args.target is None:
            address = self.ctx.ip
        else:
            address = self._obtain_address(args.target)
        try:
            self._ctx_gen = self.emu.iter_context_at(
                address,
                depth=args.depth,
                call_depth=args.call_depth,
                follow_loops=args.follow_loops,
                init_context=self.ctx if args.keep else None,
            )
            self._save_ctx()
            self.ctx = self._next_ctx()
        except dragodis.NotExistError as e:
            self.perror(f"Function doesn't exist at 0x{address:08x}")

    @cmd2.with_category(CATEGORY_EMULATION_CONTROL)
    def do_alternative(self, args):
        """
        Sets execution context to use an alternative branching path.
        Prints the difference in the branch path.
        """
        old = [f"0x{address:08x} {'(forced)' if forced else ''}" for address, forced in self.ctx.branch_history]
        self._save_ctx()
        self.ctx = self._next_ctx()
        new = [f"0x{address:08x} {'(forced)' if forced else ''}" for address, forced in self.ctx.branch_history]

        # Display difference in branch path.
        self.poutput("Branch Path:")
        for line in difflib.Differ().compare(old, new):
            if line.startswith("?"):
                continue
            color = None
            if line.startswith("+"):
                color = cmd2.Fg.GREEN
            elif line.startswith("-"):
                color = cmd2.Fg.RED
            self.poutput(cmd2.style(line, fg=color))

    next_parser = cmd2.Cmd2ArgumentParser()
    next_parser.add_argument(
        "count",
        nargs="?",
        type=int,
        default=1,
        help="Number of instructions to execute."
    )
    next_parser.add_argument(
        "-c", "--call-depth",
        action="store",
        type=int,
        default=0,
        help="Number of function calls we are allowed to emulate into. "
             "(Defaults to not emulating into any function calls.)"
    )

    @cmd2.with_category(CATEGORY_EMULATION_CONTROL)
    @cmd2.with_argparser(next_parser)
    def do_next(self, args):
        """Execute the next instruction(s)."""
        self._ctx_gen = None  # committed to this branch path.
        self._save_ctx()
        for _ in range(args.count):
            self.ctx.execute(call_depth=args.call_depth)

    undo_parser = cmd2.Cmd2ArgumentParser()
    undo_parser.add_argument(
        "count",
        nargs="?",
        type=int,
        default=1,
        help="Number of previous emulation commands to undo."
    )

    @cmd2.with_category(CATEGORY_EMULATION_CONTROL)
    @cmd2.with_argparser(undo_parser)
    def do_undo(self, args):
        """Undo the previous emulation command(s)."""
        for _ in range(args.count):
            if not self._ctx_history:
                break
            self.ctx = self._ctx_history.pop()
            self._ctx_gen = None  # TODO: Support reloading context paths.

    continue_parser = cmd2.Cmd2ArgumentParser()
    continue_parser.add_argument(
        "end_address",
        nargs="?",
        default="ret",
        help="Target address to stop instructions. Can be an address, target variable, or instruction opcode."
             "(Defaults to stopping at end of current function.)",
        completer=target_complete,
    )
    continue_parser.add_argument(
        "-c", "--call-depth",
        action="store",
        type=int,
        default=0,
        help="Number of function calls we are allowed to emulate into. "
             "(Defaults to not emulating into any function calls.)"
    )

    @cmd2.with_category(CATEGORY_EMULATION_CONTROL)
    @cmd2.with_argparser(continue_parser)
    def do_continue(self, args):
        """
        Execute until we hit a given instruction or function return (which ever comes first).
        """
        self._ctx_gen = None  # committed to this branch path.
        self._save_ctx()
        # TODO: Add breakpoint feature and ability to escape current function.
        if (end := args.end_address) != "ret":
            end = self._obtain_address(end, end)
        self.ctx.execute(end=end, call_depth=args.call_depth)

    exec_history_parser = cmd2.Cmd2ArgumentParser()
    exec_history_parser.add_argument(
        "-i", "--include-instructions",
        action="store_true",
        help="Includes the instruction text for each executed address."
    )

    @cmd2.with_category(CATEGORY_EMULATION_INFO)
    @cmd2.with_argparser(exec_history_parser)
    def do_exec_history(self, args):
        """Prints the execution history."""
        tabular_data = []
        for address in self.ctx.executed_instructions:
            entry = {"address": f"0x{address:08x}"}
            if args.include_instructions:
                entry["instruction"] = str(self.dis.get_instruction(address, ""))
            tabular_data.append(entry)
        self.ptable(tabular_data)

    branch_history_parser = cmd2.Cmd2ArgumentParser()
    branch_history_parser.add_argument(
        "-i", "--include-instructions",
        action="store_true",
        help="Includes the instruction text for the head of each block."
    )

    @cmd2.with_category(CATEGORY_EMULATION_INFO)
    @cmd2.with_argparser(branch_history_parser)
    def do_branch_history(self, args):
        """
        Prints the basic block path for the current execution context.
        NOTE: This is only displayed for 'goto' trace emulation. Using 'continue' doesn't track branching.
        """
        tabular_data = []
        for address, forced in self.ctx.branch_history:
            entry = {
                "address": f"0x{address:08x}",
                "forced": forced,
            }
            if args.include_instructions:
                entry["instruction"] = str(self.dis.get_instruction(address, ""))
            tabular_data.append(entry)
        self.ptable(tabular_data)

    @cmd2.with_category(CATEGORY_EMULATION_INFO)
    def do_call_history(self, args):
        """Prints history of called functions."""
        self.ptable([
            {
                "address": f"0x{address:08x}",
                "function": func_name,
                "args": ", ".join(f"{name}=0x{value:0x}" for name, value in func_args),
            }
            for address, func_name, func_args in self.ctx.call_history
        ])

    instruction_parser = cmd2.Cmd2ArgumentParser()
    instruction_parser.add_argument(
        "target",
        nargs="?",
        help="address or register/variable name for an address containing instruction. ",
        completer=target_complete,
    )

    @cmd2.with_category(CATEGORY_DISASSEMBLY)
    @cmd2.with_argparser(instruction_parser)
    def do_instruction(self, args):
        """
        Prints the instruction at given address or current instruction.
        """
        if args.target:
            address = self._obtain_address(args.target)
            insn = self.dis.get_instruction(address, None)
            if not insn:
                self.perror(f"Instruction does not exist at 0x{address:08x}")
                return
        else:
            insn = self.ctx.instruction
        self.poutput(insn.text)

    disassembly_parser = cmd2.Cmd2ArgumentParser()
    disassembly_parser.add_argument(
        "target",
        nargs="?",
        help="address or register/variable name for an address containing instruction.",
        completer=target_complete,
    )
    disassembly_parser.add_argument(
        "-n", "--num",
        type=int,
        default=20,
        help="Number of instructions to display."
    )

    @cmd2.with_category(CATEGORY_EMULATION_INFO)
    @cmd2.with_argparser(disassembly_parser)
    def do_disassembly(self, args):
        """
        Prints a few lines of disassembly in both directions from current instruction.
        """
        num = args.num // 2
        if args.target:
            address = self._obtain_address(args.target)
        else:
            address = self.ctx.ip

        func = self.dis.get_function(address, None)
        if not func:
            self.perror(f"Function does not exist at 0x{address:08x}")
            return

        # Print the function we are in.
        self.poutput(f"0x{func.start:08x}: {func.signature.declaration}")

        # Print instructions before.
        insns = []
        for insn in func.instructions(start=address, reverse=True):
            insns.append(insn)
            if len(insns) >= num:
                self.poutput("    ...")
                break
        for insn in reversed(insns[1:]):
            self.poutput(f"    0x{insn.address:08x}: {insn.text}")

        # Print current instruction.
        insn = self.dis.get_instruction(address)
        self.poutput(cmd2.style(f" -> 0x{insn.address:08x}: {insn.text}", fg=cmd2.Fg.LIGHT_CYAN))

        # Print instructions after.
        insns = []
        broke = False
        num = args.num - num
        for insn in func.instructions(start=address):
            insns.append(insn)
            if len(insns) >= num:
                broke = True
                break
        for insn in insns[1:]:
            self.poutput(f"    0x{insn.address:08x}: {insn.text}")
        if broke:
            self.poutput("    ...")

    @cmd2.with_category(CATEGORY_EMULATION_INFO)
    def do_spdiff(self, args):
        """
        Prints the current sp diff.
        """
        self.poutput(hex(self.ctx.sp_diff))

    code_parser = cmd2.Cmd2ArgumentParser()
    code_parser.add_argument(
        "target",
        nargs="?",
        help="address or register/variable name for an address containing function. ",
        completer=target_complete,
    )

    @cmd2.with_category(CATEGORY_DISASSEMBLY)
    @cmd2.with_argparser(code_parser)
    def do_code(self, args):
        """
        Prints the code for the current function.
        """
        if args.target:
            address = self._obtain_address(args.target)
        else:
            address = self.ctx.ip
        if func := self.dis.get_function(address, None):
            self.poutput(func.source_code)
        else:
            self.perror(f"Address not within a function: 0x{address:08x}")

    @cmd2.with_category(CATEGORY_DISASSEMBLY)
    def do_stack(self, args):
        """
        Prints the stack frame for the current function.
        NOTE: Use 'variables' command to get more information.
        """
        if func := self.dis.get_function(self.ctx.ip, None):
            self.ptable([
                {
                    "offset": hex(var.stack_offset),
                    "size": var.size,
                    "data_type": var.data_type,
                    "name": var.name,
                }
                for var in func.stack_frame
            ])
        else:
            self.perror("Not currently in a function")

    strings_parser = cmd2.Cmd2ArgumentParser()
    strings_parser.add_argument(
        "target",
        nargs="?",
        help="Output string value at address.",
        completer=target_complete,
    )
    strings_parser.add_argument(
        "--min",
        type=int,
        default=3,
        help="Minimum length for a valid string."
    )
    strings_parser.add_argument(
        "--raw",
        action="store_true",
        help="Whether to write out the raw binary of the string when using target. "
             "Recommend redirecting output to a file or piped command."
    )

    @cmd2.with_category(CATEGORY_DISASSEMBLY)
    @cmd2.with_argparser(strings_parser)
    def do_strings(self, args):
        """
        Prints the detected strings within the disassembly.
        """
        if args.target:
            address = self._obtain_address(args.target)
            for string in self.dis.strings(min_length=args.min):
                if string.address == address:
                    if args.raw:
                        sys.stdout.buffer.write(string.data)
                    else:
                        self.poutput(string.value)
                    break
        else:
            self.ptable([
                {
                    "address": f"0x{string.address:08x}",
                    "size": len(string.data),
                    "string": string.value,
                }
                for string in self.dis.strings(min_length=args.min)
            ])

    functions_parser = cmd2.Cmd2ArgumentParser()
    functions_parser.add_subparsers()

    @cmd2.with_category(CATEGORY_DISASSEMBLY)
    @cmd2.with_argparser(functions_parser)
    def do_functions(self, args):
        """
        Prints the functions within the disassembly.
        """
        # Handle subcommands.
        if handler := args.cmd2_handler.get():
            handler(args)
            return

        self.ptable([
            {
                "start": f"0x{func.start:08x}",
                "end": f"0x{func.end:08x}",
                "name": func.name,
            }
            for func in self.dis.functions()
        ])

    functions_create_parser = cmd2.Cmd2ArgumentParser()
    functions_create_parser.add_argument(
        "address",
        help="Target name/address that would be contained in the function.",
    )

    @cmd2.as_subcommand_to("functions", "create", functions_create_parser, help="Creates a new function.")
    def functions_create(self, args):
        """
        Attempts to define a new function at given address.
        """
        address = self._obtain_address(args.address)
        if self.dis.get_function(address, None):
            self.pwarning(f"Function already exists at 0x{address:08x}")
        elif func := func_utils.create_function(self.dis, address):
            self.pfeedback(f"Function created: {func.name} @ 0x{func.start:08x}")
        else:
            self.perror(f"Unable to create a function at 0x{address:08x}")
        self._cache_function_names()

    @cmd2.with_category(CATEGORY_DISASSEMBLY)
    def do_segments(self, args):
        """
        Prints the segments within the disassembly.
        """
        self.ptable([
            {
                "start": f"0x{seg.start:08x}",
                "end": f"0x{seg.end:08x}",
                "size": seg.end - seg.start,
                "name": seg.name,
                "permissions": seg.permissions.name.upper() if seg.permissions else None,
                "bit_size": seg.bit_size,
                "initialized": seg.initialized,
            }
            for seg in self.dis.segments
        ])

    @cmd2.with_category(CATEGORY_DISASSEMBLY)
    def do_imports(self, args):
        """
        Prints the imports within the disassembly.
        """
        tabular_data = []
        for imp in self.dis.imports:
            if thunk_address := imp.thunk_address:
                thunk_address = f"0x{thunk_address:08x}"
            tabular_data.append({
                "address": f"0x{imp.address:08x}",
                "thunk_address": thunk_address,
                "name": imp.name,
                "namespace": imp.namespace,
                "num_references": len(list(imp.references_to)),
                "num_calls": len(list(imp.calls_to)),
            })
        self.ptable(tabular_data)

    @cmd2.with_category(CATEGORY_DISASSEMBLY)
    def do_exports(self, args):
        """
        Prints the exports within the disassembly.
        """
        tabular_data = []
        for export in self.dis.exports:
            tabular_data.append({
                "address": f"0x{export.address:08x}",
                "name": export.name,
                "num_references": len(list(export.references_to)),
            })
        self.ptable(tabular_data)

    references_parser = cmd2.Cmd2ArgumentParser()
    references_parser.add_argument(
        "target",
        help="Target name/address to get references.",
        completer=target_complete,
    )
    references_parser.add_argument(
        "--direction",
        choices=["to", "from", "both"],
        default="both",
        help="Whether to get references to, from or both directions. (Defaults to both)"
    )
    references_parser.add_argument(
        "-i", "--include-instructions",
        action="store_true",
        help="Includes the instruction text for each address."
    )

    @cmd2.with_category(CATEGORY_DISASSEMBLY)
    @cmd2.with_argparser(references_parser)
    def do_references(self, args):
        """
        Prints the references to or from a given target in the disassembly.
        """
        address = self._obtain_address(args.target)

        refs = []
        if args.direction in ("both", "to"):
            refs.append(("to", self.dis.references_to(address)))
        if args.direction in ("both", "from"):
            refs.append(("from", self.dis.references_from(address)))

        tabular_data = []
        for direction, ref_gen in refs:
            for ref in ref_gen:
                entry = {
                    "direction": direction,
                    "type": ref.type.name,
                    "from_address": f"0x{ref.from_address:08x}",
                    "from_text": None,
                    "to_address": f"0x{ref.to_address:08x}",
                    "to_text": None,
                }
                if args.include_instructions:
                    if (line := self.dis.get_line(ref.from_address, None)) and line.value is not None:
                        entry["from_text"] = str(line.value)
                    if (line := self.dis.get_line(ref.to_address, None)) and line.value is not None:
                        entry["to_text"] = str(line.value)
                else:
                    del entry["from_text"]
                    del entry["to_text"]
                tabular_data.append(entry)
        self.ptable(tabular_data)

    search_parser = cmd2.Cmd2ArgumentParser()
    search_parser.add_argument(
        "pattern",
        help="Regex pattern to search"
    )
    search_parser.add_argument(
        "-s", "--segment",
        help="Restrict search to given segment.",
        choices_provider=lambda self: [seg.name for seg in self.dis.segments],
    )
    search_parser.add_argument(
        "-n", "--num",
        type=int,
        help="Restrict number of results. (Defaults to all results.)",
    )

    @cmd2.with_category(CATEGORY_DISASSEMBLY)
    @cmd2.with_argparser(search_parser)
    def do_search(self, args):
        """
        Searches disassembly for given regex pattern.

        e.g.
            search "\xea.{3}\x11"
        """
        pattern = rugosa.re.compile(args.pattern.encode(), re.DOTALL)
        tabular_data = []
        for i, match in enumerate(pattern.finditer(self.dis, args.segment), start=1):
            line = self.dis.get_line(match.start())
            func = self.dis.get_function(line.address, None)
            seg = self.dis.get_segment(line.address)
            tabular_data.append({
                "segment": seg.name,
                "address": f"0x{line.address:08x}",
                "text": str(line.value),
                "function": func.name if func else None,
                "data": trepr(match.group()),
            })
            if args.num and i == args.num:
                break
        self.ptable(tabular_data)

    info_parser = cmd2.Cmd2ArgumentParser()
    info_parser.add_argument(
        "target",
        nargs="?",
        help="address or target variable address to get information.",
        completer=target_complete,
    )

    @cmd2.with_category(CATEGORY_DISASSEMBLY)
    @cmd2.with_argparser(info_parser)
    def do_info(self, args):
        """Prints information about given address or current instruction."""
        if args.target:
            address = self._obtain_address(args.target)
        else:
            address = self.ctx.ip

        line = self.dis.get_line(address, None)
        if not line:
            self.perror(f"Address not found 0x{address:08x}")
            return
        function = self.dis.get_function(address, None)
        address = line.address
        value = line.value

        for imp in self.dis.imports:
            if address in (imp.address, imp.thunk_address):
                break
        else:
            imp = None

        for export in self.dis.exports:
            if address == export.address:
                break
        else:
            export = None

        registers = []
        for register in self.ctx.registers:
            for reg_name in register.names:
                if register[reg_name] == address:
                    registers.append(reg_name)

        operands = []
        for operand in self.ctx.operands:
            if address in (operand.addr, operand.value):
                operands.append(operand)

        variables = []
        for variable in self.ctx.variables:
            if address in (variable.addr, variable.value):
                variables.append(variable)

        if line.is_integer:
            value = hex(value)
        elif not line.is_code:
            value = trepr(value)

        tabular_data = [
            ["Name", line.name or ""],
            ["Address", f"0x{address:08x}"],
            ["Size", line.size],
            ["Location", self.dis.get_segment(address, "<stack>" if address <= 0x1180000 else "<heap>")],
            ["Function", function.signature if function else ""],
            ["Type", line.type.name],
            ["Value", value],
            ["References To", len(list(line.references_to))],
            ["References From", len(list(line.references_from))],
            ["Import", imp or ""],
            ["Export", export or ""],
            ["Registers", ", ".join(map(str, registers))],
            ["Operands", "\n".join(f"{i}: {op.text}" for i, op in enumerate(operands))],
            ["Variables", ", ".join(var.name for var in variables)],
        ]
        self.ptable(tabular_data, headers=())

        if self.ctx.memory.is_mapped(address):
            self.poutput("\n## Data")
            self.phexdump(self.ctx.memory.read(address, line.size), start_address=address)

    @cmd2.with_category(CATEGORY_EMULATION_ARTIFACTS)
    def do_operands(self, args):
        """
        Prints the operands at the current instruction.
        """
        self.ptable([
            {
                "index": operand.idx,
                "text": operand.text,
                "address": f"0x{operand.addr:08x}" if operand.addr else "",
                "value": repr(operand.value),
                "width": operand.width,
            }
            for operand in self.ctx.operands
        ])

    registers_parser = cmd2.Cmd2ArgumentParser()
    registers_parser.add_argument(
        "name",
        nargs="?",
        help="Print results of specific register.",
        choices_provider=lambda self: self.ctx.registers.names,
    )
    registers_parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Print all registers, including zero values."
    )

    @cmd2.with_category(CATEGORY_EMULATION_ARTIFACTS)
    @cmd2.with_argparser(registers_parser)
    def do_registers(self, args):
        """
        Print values of individual register or all registers.

        For brevity, this only prints out the registers with a nonzero value. Use --all to display all.
        """
        if name := args.name:
            try:
                self.poutput(f"0x{self.ctx.registers[name]:08x}")
            except AttributeError:
                self.perror("Invalid register name.")
        else:
            self.ptable([
                {
                    "family": reg.family_name,
                    "value": f"0x{reg._value:08x}"
                }
                for reg in self.ctx.registers
                if args.all or reg._value
            ])

    variables_parser = cmd2.Cmd2ArgumentParser()
    variables_parser.add_argument(
        "target",
        nargs="?",
        help="Output value of given variable name/address.",
        choices_provider=lambda self: [*self.ctx.variables.names, *(hex(addr) for addr in self.ctx.variables.addrs)],
    )
    variables_parser.add_argument(
        "--raw",
        action="store_true",
        help="Whether to write out the raw binary of the variable when using target. "
             "Recommend redirecting output to a file or piped command."
    )

    @cmd2.with_category(CATEGORY_EMULATION_ARTIFACTS)
    @cmd2.with_argparser(variables_parser)
    def do_variables(self, args):
        """Print values of variables."""
        if target := args.target:
            try:
                target = auto_int(target)
            except ValueError:
                pass
            var = self.ctx.variables.get(target)
            if not var:
                self.perror("Invalid variable name or address.")
                return
            if args.raw:
                sys.stdout.buffer.write(var.data)
            else:
                self.poutput(repr(var.value))
        else:
            tabular_data = []
            for var in sorted(self.ctx.variables):
                data_type_str = var.data_type
                if var.count > 1 and data_type_str != "func_ptr":
                    data_type_str += f"[{var.count}]"
                if stack_offset := getattr(var, "stack_offset", None):
                    stack_offset = hex(stack_offset)
                tabular_data.append({
                    "address": f"0x{var.addr:08x}",
                    "stack_offset": stack_offset,
                    "name": var.name,
                    "type": data_type_str,
                    "size": var.size,
                    "value": trepr(var.value),
                })
            self.ptable(tabular_data)

    def _print_func_args(self, func_args):
        tabular_data = []
        for arg in func_args:
            # If argument is a pointer, show the first few bytes of the referenced data.
            if self.ctx.memory.is_mapped(arg.value):
                data = self.ctx.memory.read(arg.value, 50)
                data = repr(data)[:50] + ".."
            else:
                data = ""
            tabular_data.append({
                "ordinal": arg.ordinal,
                "location": str(arg.location),
                "type": arg.type,
                "width": arg.width,
                "name": arg.name,
                "address": (f"0x{arg.addr:08x}" if arg.addr is not None else ""),
                "value": hex(arg.value),
                "referenced data": data,
            })
        self.ptable(tabular_data)

    arguments_parser = cmd2.Cmd2ArgumentParser()
    arguments_parser.add_argument(
        "target",
        nargs="?",
        help="address or register/variable name for function start address. "
             "Defaults to the call current operand if a call instruction.",
        completer=target_complete,
    )
    arguments_parser.add_argument(
        "-n", "--num-args",
        action="store",
        type=int,
        default=None,
    )

    @cmd2.with_category(CATEGORY_EMULATION_ARTIFACTS)
    @cmd2.with_argparser(arguments_parser)
    def do_arguments(self, args):
        """
        Prints the function arguments currently set given a function provided or at a current call instruction.
        """
        if target := args.target:
            address = self._obtain_address(target)
        else:
            address = None
        try:
            func_sig = self.ctx.get_function_signature(address, num_args=args.num_args)
            if not func_sig:
                self.perror("No operand to pull function address.")
                return
        except dragodis.NotExistError as e:
            self.perror(str(e))
            return

        self.poutput(f"0x{func_sig.address:08x}: {func_sig.declaration}")

        if func_args := func_sig.arguments:
            self._print_func_args(func_args)

    @cmd2.with_category(CATEGORY_EMULATION_ARTIFACTS)
    def do_parameters(self, args):
        """
        Prints the function arguments passed in as parameters for the current function.
        """
        func = self.dis.get_function(self.ctx.ip)
        func_sig = self.ctx.get_function_signature(func.start)
        self.poutput(f"0x{func_sig.address:08x}: {func_sig.declaration}")
        self._print_func_args(self.ctx.passed_in_args)

    @cmd2.with_category(CATEGORY_EMULATION_ARTIFACTS)
    def do_stdout(self, args):
        """
        Prints out current stdout of context.
        """
        self.poutput(self.ctx.stdout)

    @cmd2.with_category(CATEGORY_EMULATION_ARTIFACTS)
    def do_actions(self, args):
        """
        Prints out the actions that have taken place within the current context.
        """
        self.ptable([
            {
                "address": f"0x{action.ip:08x}",
                "action": action.__class__.__name__,
                "handle": hex(action.handle) if action.handle is not None else None,
                "attributes": ", ".join(f"{name}={trepr(value)}" for name, value in action if name not in ("ip", "handle")),
            }
            for action in self.ctx.actions
        ])

    @cmd2.with_category(CATEGORY_EMULATION_ARTIFACTS)
    def do_objects(self, args):
        """
        Prints out the high-level objects that have been generated within the current context.
        """
        if self.ctx.files:
            self.poutput("## Files")
            self.onecmd("files", add_to_history=False)
            self.poutput("\n\n")

        if self.ctx.reg_keys:
            self.poutput("## Registry Keys")
            self.onecmd("regkeys", add_to_history=False)
            self.poutput("\n\n")

        if self.ctx.services:
            self.poutput("## Services")
            self.onecmd("services", add_to_history=False)
            self.poutput("\n\n")

    files_parser = cmd2.Cmd2ArgumentParser()
    files_parser.add_argument(
        "handle",
        nargs="?",
        type=auto_int,
        help="Output raw data for given file handle.",
        choices_provider=lambda self: [hex(file.handle) for file in self.ctx.files],
    )

    @cmd2.with_category(CATEGORY_EMULATION_ARTIFACTS)
    @cmd2.with_argparser(files_parser)
    def do_files(self, args):
        """
        Prints out the file objects that have been generated within the current context.
        """
        if args.handle:
            for file in self.ctx.files:
                if file.handle == args.handle:
                    sys.stdout.buffer.write(file.data)
                    return
        else:
            self.ptable([
                {
                    "handle": hex(file.handle),
                    "path": file.path,
                    "mode": file.mode,
                    "size": len(file.data),
                    "closed": file.closed,
                    "deleted": file.deleted,
                    "data": trepr(file.data),
                }
                for file in self.ctx.files
            ])

    @cmd2.with_category(CATEGORY_EMULATION_ARTIFACTS)
    def do_regkeys(self, args):
        """
        Prints out the registry key objects that have been generated within the current context.
        """
        self.ptable([
            {
                "handle": hex(regkey.handle),
                "root_key": regkey.root_key,
                "sub_key": regkey.sub_key,
            }
            for regkey in self.ctx.reg_keys
        ])

    @cmd2.with_category(CATEGORY_EMULATION_ARTIFACTS)
    def do_services(self, args):
        """
        Prints out the service objects that have been generated within the current context.
        """
        self.ptable([
            {
                "handle": hex(service.handle),
                "name": service.name,
                "binary_path": service.binary_path,
                "display_name": service.display_name,
                "description": service.description,
            }
            for service in self.ctx.services
        ])

    memory_parser = cmd2.Cmd2ArgumentParser()
    memory_parser.add_argument(
        "target",
        nargs="?",
        help="Address or register/variable name for starting point to read memory from.",
        completer=target_complete,
    )
    memory_parser.add_argument(
        "-n", "--num",
        type=int,
        default=256,
        help="Number of bytes to read."
    )
    memory_parser.add_argument(
        "--raw",
        action="store_true",
        help="Whether to write out the raw binary of read memory. "
             "Recommend redirecting output to a file or piped command."
    )

    @cmd2.with_category(CATEGORY_EMULATION_ARTIFACTS)
    @cmd2.with_argparser(memory_parser)
    def do_memory(self, args):
        """Prints out allocated memory blocks or read from given address."""
        if args.target:
            address = self._obtain_address(args.target)
            data = self.ctx.memory.read(address, args.num)
            if args.raw:
                sys.stdout.buffer.write(data)
            else:
                self.phexdump(data, start_address=address)
        else:
            # Display allocated memory blocks.
            self.ptable([
                {
                    "start": f"0x{address:08x}",
                    "end": f"0x{address + size:08x}",
                    "size": size,
                }
                for address, size in self.ctx.memory.blocks
            ])

    @cmd2.with_category(CATEGORY_EMULATION_INFO)
    def do_dump(self, args):
        """
        Prints out a report of all information.
        """
        self.poutput("# Rugosa Emulation Report")
        self.onecmd("status", add_to_history=False)
        self.poutput("\n\n")

        self.poutput("## Disassembly")
        self.onecmd("disassembly", add_to_history=False)
        self.poutput("\n\n")

        self.poutput("## Operands")
        self.onecmd("operands", add_to_history=False)
        self.poutput("\n\n")

        self.poutput("## Registers")
        self.onecmd("registers", add_to_history=False)
        self.poutput("\n\n")

        self.poutput("## Variables")
        self.onecmd("variables", add_to_history=False)
        self.poutput("\n\n")

        self.onecmd("objects", add_to_history=False)
        self.poutput("\n\n")

        self.poutput("## Branch History")
        self.onecmd("branch_history -i", add_to_history=False)
        self.poutput("\n\n")

        self.poutput("## Call History")
        self.onecmd_plus_hooks("call_history", add_to_history=False)
        self.poutput("\n\n")


@contextlib.contextmanager
def temporary_file(binary_path: Path) -> Path:
    with tempfile.TemporaryDirectory(prefix="rugosa_") as tmp_dir:
        binary_copy = Path(tmp_dir) / binary_path.name
        shutil.copy(binary_path, binary_copy)
        yield binary_copy


def main():
    parser = argparse.ArgumentParser(
        "rugosa",
        description="Rugosa Interactive Shell",
        epilog=(
            "Extra arguments will be passed along to the shell as commands to run on startup.\n"
            "e.g. `rugosa binary.exe 'goto 0x1234' dis`"
        )
    )
    parser.add_argument(
        "binary",
        type=Path,
        help="Input binary file to analyze."
    )
    parser.add_argument(
        "-b", "--backend",
        choices=[dragodis.BACKEND_GHIDRA.lower(), dragodis.BACKEND_IDA.lower()],
        default=dragodis.BACKEND_DEFAULT.lower(),
        type=str.lower,
        help="Backend disassembler used to analyze binary file.",
    )
    parser.add_argument(
        "-p", "--processor",
        help="Processor spec to use. (Defaults to auto-detection by underlying disassembler)",
    )
    parser.add_argument(
        "-n", "--nologo",
        action="store_true",
        help="Suppresses the startup text."
    )
    parser.add_argument(
        "-t", "--tmp", "--temp",
        action="store_true",
        help="Copies sample to a temporary directory before starting up. "
             "This helps to avoid conflicts when you already have the sample open in a disassembler."
    )
    parser.add_argument(
        "--history-file",
        default=None,
        help="File to save history of commands. Defaults to <binary path>.rugosa. (Use `--nohist` to turn this off)",
    )
    parser.add_argument(
        "--nohist",
        action="store_true",
        help="Do not save a history of commands."
    )
    parser.add_argument(
        "-s", "--startup-script",
        default=os.environ.get("RUGOSA_STARTUP_SCRIPT", ""),
        help="Path to startup script to be executed. Defaults to path supplied in RUGOSA_STARTUP_SCRIPT if it exists."
    )
    parser.add_argument(
        "--nocache",
        action="store_true",
        help="Turn off the precaching of function and imports names on startup. "
             "This is used for tab completion, but may not be useful if using a one-off script. "
             "(This is automatically enabled if a 'quit' or 'exit' is within the command line.)"
    )
    args, rest = parser.parse_known_args()
    sys.argv[1:] = rest

    processor = {
        "arm": dragodis.PROCESSOR_ARM,
        "arm64": dragodis.PROCESSOR_ARM64,
        "x86": dragodis.PROCESSOR_X86,
        "x64": dragodis.PROCESSOR_X64,
    }.get(args.processor, args.processor)

    if not args.binary.exists():
        raise parser.error(f"binary: '{args.binary}' doesn't exist.")

    if args.startup_script and not Path(args.startup_script).exists():
        raise parser.error(f"STARTUP_SCRIPT: '{args.startup_script}' doesn't exist.")

    if args.tmp:
        binary = temporary_file(args.binary)
    else:
        binary = contextlib.nullcontext(args.binary)

    if args.nohist:
        history_file = None
    else:
        history_file = args.history_file or f"{args.binary}.rugosa"

    precache = not args.nocache
    if "quit" in rest or "exit" in rest:
        precache = False

    # Run detached to prevent Ctrl+C from killing the rpyc connection (IDA only)
    with binary as binary_path:
        with dragodis.open_program(binary_path, disassembler=args.backend, processor=processor, detach=True) as dis:
            app = App(
                dis,
                logo=not args.nologo,
                history_file=history_file,
                startup_script=args.startup_script,
                precache=precache,
            )
            sys.exit(app.cmdloop())


if __name__ == "__main__":
    main()
