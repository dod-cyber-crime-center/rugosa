"""
Interface for instruction management.
"""
from __future__ import annotations

import logging
from copy import deepcopy
from typing import List, TYPE_CHECKING

import dragodis.interface
from dragodis import NotExistError

from . import utils
from .operands import Operand
from .exceptions import EmulationError

if TYPE_CHECKING:
    from rugosa.emulation.cpu_context import ProcessorContext

logger = logging.getLogger(__name__)


class Instruction:
    """
    Wraps a dragodis Instruction object in order to represent the dynamic
    version of an instruction based on the connected processor context.
    """

    # Cache for keeping track of instructions and their operand indexes.
    _operand_indices = {}

    # Class used for creating new operands.
    _operand_class = Operand

    def __init__(self, cpu_context: ProcessorContext, ip):
        self.ip = ip
        self._cpu_context = cpu_context
        self.__insn = None

    def __deepcopy__(self, memo):
        # When we deep copy, clear out the __insn attribute so we don't
        # run into any serialization issues with bridged objects.
        deepcopy_method = self.__deepcopy__
        self.__deepcopy__ = None
        self.__insn = None
        copy = deepcopy(self, memo)
        self.__deepcopy__ = deepcopy_method
        return copy

    def __str__(self):
        return f"<{self.__class__.__name__} 0x{self.ip:08x} - {self.text}>"

    @property
    def _insn(self) -> dragodis.interface.Instruction:
        if not self.__insn:
            try:
                insn = self._cpu_context.emulator.disassembler.get_instruction(self.ip)
            except dragodis.NotExistError:
                # TODO: Should we just allow the NotExistError error to happen?
                raise EmulationError(f"Failed to get instruction at 0x{self.ip:X}")
            self.__insn = insn
        return self.__insn

    @property
    def mnem(self) -> str:
        """Opcode mnemonic."""
        return self._insn.mnemonic

    # TODO: Move to dragodis
    @property
    def root_mnem(self) -> str:
        """
        Opcode mnemonic without any extensions such as condition codes, data type, etc.

        e.g.
            MOVSEQ -> MOV
        """
        return self._insn.root_mnemonic

    @property
    def text(self) -> str:
        """Disassembled code."""
        return self._insn.text

    @property
    def is_terminal(self) -> bool:
        return self._insn.is_return

    @property
    def next_ip(self) -> int:
        """Obtains the address for the next instruction after this one."""
        return self._insn.line.next.address

    # TODO: Overwrite this in ARM to handle that special case.
    @property
    def operands(self) -> List[_operand_class]:
        return [
            self._operand_class(self._cpu_context, operand)
            for operand in self._insn.operands
        ]

    def _record_func_args(self):
        """
        Reset stack pointer reference and
        record function argument variables if we are executing the beginning of a function.
        """
        try:
            func_obj = self._cpu_context.emulator.disassembler.get_function(self.ip)
            if func_obj.start != self.ip:
                return
        except NotExistError:
            return

        # Reset the sp_start
        self._cpu_context._sp_start = self._cpu_context.sp

        # Add the passed in arguments to the variables map.
        for arg in self._cpu_context.passed_in_args:
            addr = arg.addr
            # TODO: Support variables from registers?
            if addr is not None:
                if arg.is_stack:
                    try:
                        stack_variable = func_obj.stack_frame[arg.name]
                        self._cpu_context.variables.add(addr, stack_variable)
                    except (KeyError, ValueError):
                        logger.warning(f"Failed to get stack information for function argument: {repr(arg)}")
                else:
                    self._cpu_context.variables.add(addr)

    def get_hooks(self, pre=True):
        """
        Retrieves callback hooks for the given instruction.
        :param pre: Whether to retrieve pre or post execution hooks.
        """
        return (
            self._cpu_context.emulator.get_instruction_hooks(self.ip, pre=pre)
            + self._cpu_context.emulator.get_instruction_hooks(self.mnem, pre=pre)
        )

    def _execute_hooks(self, pre=True):
        """
        Executes instructions hooks for the given start
        """
        for hook in self.get_hooks(pre=pre):
            try:
                hook(self._cpu_context, self)
            except RuntimeError:
                raise  # Allow RuntimeError exceptions to be thrown.
            except Exception as e:
                logger.debug("Failed to execute instruction hook with error: %s", e)

    def _execute(self):
        """
        Internal execute code used to execute the instruction itself and
        perform any custom tasks specific to the architecture.
        """
        emulator = self._cpu_context.emulator
        opcode_func = (
            emulator.get_opcode_hook(self.mnem)  # e.g. "bleq"
            or emulator.get_opcode_hook(self.root_mnem)  # e.g. "bl" from "bleq"
        )
        if opcode_func:
            opcode_func(self._cpu_context, self)
        else:
            logger.debug("%s instruction not implemented.", self.mnem)

    # TODO: All variable add_references() should be done here instead of in Operand class.
    def execute(self):
        """
        Emulate the instruction and store results in the context.
        """
        # Log a header line for debug messages of this instruction.
        # This is simpler and faster then trying to include the information at each log line
        logger.debug("[0x%X %03X] :: %s", self.ip, self._cpu_context.sp_diff, self.mnem)

        # Set instruction pointer to where we are currently executing.
        self._cpu_context.ip = self.ip

        # Extra processing if we are at the start of a function.
        self._record_func_args()

        # Run any pre-hooks first.
        self._execute_hooks(pre=True)

        # Execute the instruction.
        try:
            self._execute()
        except Exception:
            logger.exception("Failed to execute address 0x%X: %s", self.ip, self.text)

        # Record any variables encountered in the operands.
        for operand in self.operands:
            var = operand._operand.variable
            if var:
                self._cpu_context.variables.add(
                    operand.addr or operand.value, var, reference=self._cpu_context.ip
                )

        # Record executed instruction.
        self._cpu_context.executed_instructions.append(self.ip)

        # Run any post-hooks.
        self._execute_hooks(pre=False)

        # Add a blank space to help visualy separate logs for each instruction.
        logger.debug("  ")

        # After execution, set instruction pointer to next instruction assuming
        # standard code flow and if no jump was made.
        if self._cpu_context.ip == self.ip:
            disassembler = self._cpu_context.emulator.disassembler
            self._cpu_context.ip = disassembler.get_line(self.ip).next.address

    def execute_call_hooks(self, func_name, func_ea):
        """
        Collect call history and emulates the affects of the function call
        by executing call hooks.

        :param func_name: Name of the function (or empty string)
        :param func_ea: Address of function to call.
        """
        # Tell context that we are currently emulating a function hook.
        # This information is import for things like pulling out function arguments out correctly.
        self._cpu_context.hooking_call = func_ea

        try:
            # Report on function call and their arguments.
            arg_objs = self._cpu_context.get_function_args(func_ea)
            args = [arg_obj.value for arg_obj in arg_objs]
            self._cpu_context.func_calls[self.ip] = (func_name, args)

            # Emulate the effects of any known builtin functions.
            func = self._cpu_context.emulator.get_call_hook(func_ea)
            if not func:
                func = self._cpu_context.emulator.get_call_hook(func_name)
                if not func:
                    # Try one more time with a sanitized name.
                    func_name = utils.sanitize_func_name(func_name)
                    func = self._cpu_context.emulator.get_call_hook(func_name)
            if func:
                try:
                    logger.debug(
                        "Emulating %s(%s)",
                        func_name,
                        ", ".join(f"{arg_obj.name}={hex(arg_obj.value)}" for arg_obj in arg_objs)
                    )
                    logger.debug("Running hook: %r", func)
                    ret = func(self._cpu_context, func_name, args)
                    if ret is True:
                        ret = 1
                    elif ret is False:
                        ret = 0
                    # Set return value to rax
                    if ret is not None:
                        if not isinstance(ret, int):
                            raise TypeError(f"Invalid return type. Expected 'int' but got '{type(ret)}'")
                        self._cpu_context.ret = ret
                except RuntimeError:
                    raise  # Allow RuntimeError exceptions to be thrown.
                except Exception as e:
                    logger.debug("Failed to emulate builtin function: %s() with error: %s", func_name, e)

        finally:
            self._cpu_context.hooking_call = None
