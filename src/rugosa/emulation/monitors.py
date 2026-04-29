"""
Classes which monitor the emulation flow for data collection purposes.
"""
from __future__ import annotations
import collections
import inspect
import logging
import warnings
from typing import Type, Iterable, TypeVar, TYPE_CHECKING

from rugosa.emulation.monitor import ScopedMonitor, Monitor
from rugosa.emulation.objects import File, RegKey, Service, Object
from rugosa.emulation.exceptions import MaxExecutionHit
from rugosa.emulation.stack_strings import StackStringsMonitor

if TYPE_CHECKING:
    from rugosa.emulation.cpu_context import ProcessorContext
    from rugosa.emulation.instruction import Instruction
    from rugosa.emulation.actions import Action


logger = logging.getLogger(__name__)

__all__ = [
    "ActionMonitor",
    "ObjectMonitor",
    "MaxExecutionMonitor",
    "VariableMonitor",
    "InstructionHooks",
    "StackStringsMonitor",
]


class ActionMonitor(ScopedMonitor):
    """
    Collects and dedups the actions that have been observed.
    """

    def __init__(self, scope="instruction"):
        super().__init__(scope)
        self._actions = set()
        self._previous = set()

    def __iter__(self) -> Iterable[Action]:
        yield from sorted(self._actions)

    def latest(self) -> list[Action]:
        """
        Returns a list of the latest new results since last time this function was run.
        """
        new_actions = self._actions - self._previous
        self._previous = self._actions.copy()
        return list(new_actions)

    def clear(self):
        self._actions = set()

    def hook(self, context: ProcessorContext, instruction: Instruction):
        self._actions.update(context.actions)


T = TypeVar("T")


class ObjectMonitor(ScopedMonitor):
    """
    Collects and optionally dedups the objects that have been observed.
    """

    def __init__(self, scope="instruction", unique: bool = True):
        """
        :param scope: Frequency to collect new observed objects.
        :param unique: Whether to dedup objects based on content.
        """
        super().__init__(scope)
        self._unique = unique
        self._objects = {}
        self._latest_keys = []

    def __iter__(self) -> Iterable[Object]:
        yield from sorted(self._objects.values(), key=lambda obj: obj.references)

    def latest(self) -> list[Object]:
        """
        Returns a list of the latest new results since last time this function was run.
        """
        objects = [self._objects[key] for key in self._latest_keys]
        self._latest_keys = []
        return objects

    def clear(self):
        self._latest_keys = []
        self._objects.clear()

    def hook(self, context: ProcessorContext, instruction: Instruction):
        for object in context.objects:
            key = object.content_hash() if self._unique else hash(object)
            if key not in self._objects:
                self._objects[key] = object
                self._latest_keys.append(key)

    def query(self, obj_type: Type[T], **conditions) -> Iterable[T]:
        """
        Queries collection for objects of specific types.
        """
        for obj in self:
            if (
                isinstance(obj, obj_type)
                and all(getattr(obj, attr_name) == value for attr_name, value in conditions.items())
            ):
                yield obj

    def files(self) -> Iterable[File]:
        return self.query(File)

    def reg_keys(self) -> Iterable[RegKey]:
        return self.query(RegKey)

    def services(self) -> Iterable[Service]:
        return self.query(Service)


class MaxExecutionMonitor(Monitor):
    """
    Stops execution if max number of instructions have be emulated.
    """

    def __init__(self, total: int):
        self.total = total
        self.count = 0

    def reset(self):
        self.count = 0

    def post_instruction(self, context: ProcessorContext, instruction: Instruction):
        self.count += 1
        if self.count >= self.total:
            raise MaxExecutionHit("Hit maximum number of instructions.")


class VariableMonitor(Monitor):
    """
    Records observed variables in emulation.
    """

    def function_start(self, context: ProcessorContext, instruction: Instruction):
        # Record passed in arguments if we are at the start of a function.
        func = context.emulator.disassembler.get_function(context.ip)
        for arg in context.passed_in_args:
            addr = arg.addr
            # TODO: Support variables from registers?
            if addr is not None:
                if arg.is_stack:
                    try:
                        stack_variable = func.stack_frame[arg.name]
                        context.variables.add(addr, stack_variable)
                    except (KeyError, ValueError):
                        # TODO: passed in arguments aren't found on the stack for IDA.
                        #   This is due to IDA not adding argument names in function signature.
                        logger.warning(f"Failed to get stack information for function argument: {repr(arg)}")
                else:
                    context.variables.add(addr)

    def post_instruction(self, context: ProcessorContext, instruction: Instruction):
        # Record any variables encountered in the operands.
        for operand in instruction.operands:
            var = operand._operand.variable
            if var:
                context.variables.add(operand.addr or operand.value, var, reference=context.ip)


class InstructionHooks(Monitor):
    """
    Provides support for legacy instruction hooking.
    """

    def __init__(self):
        self._instruction_hooks = collections.defaultdict(list)

    def clear(self):
        self._instruction_hooks = collections.defaultdict(list)

    def hook(self, opcode_or_ea, func, pre=True):
        """
        Hooks all instructions of a given opcode or at specific address with a custom
        user defined function.

        :param opcode_or_ea: name of the opcode or address of the instruction to hook (e.g. "pop")
        :param func: Function to run while before or after emulating the instruction.
            Function must accept 2 arguments: cpu_context, instruction
        :param pre: Whether to run the function before or after the instruction has been emulated.
            (defaults to before)
        """
        # Convert callbacks using the older signature to the newer.
        sig = inspect.signature(func)
        num_parameters = len(sig.parameters)
        if num_parameters == 4:
            warnings.warn(
                "Instruction callbacks using 4 parameters is deprecated. "
                "Please update your callback to use 2 parameters: cpu_context and instruction",
                DeprecationWarning
            )
            orig_func = func
            func = lambda ctx, insn: orig_func(ctx, insn.ip, insn.mnem, insn.operands)
        elif num_parameters != 2:
            raise TypeError(f"Instruction hook should only accept 2 parameters. Got {num_parameters}")

        if isinstance(opcode_or_ea, str):
            opcode_or_ea = opcode_or_ea.lower()
        self._instruction_hooks[(opcode_or_ea, pre)].append(func)

    def get(self, opcode_or_ea, pre=True):
        """
        Gets instruction hook for given opcode mnemonic or address.

        :param opcode_or_ea: Opcode mnemonic or address of the instruction
        :param pre: Whether to run the function before or after the instruction has been emulated.
            (defaults to before)

        :return: A list of hook functions.
        """
        if isinstance(opcode_or_ea, str):
            opcode_or_ea = opcode_or_ea.lower()

        return self._instruction_hooks.get((opcode_or_ea, pre), [])

    def execute(self, context: ProcessorContext, instruction: Instruction, pre: bool):
        """
        Executes instruction hooks for given instruction.
        """
        hooks = (
            self.get(instruction.ip, pre)
            + self.get(instruction.mnem, pre)
        )
        for hook in hooks:
            try:
                hook(context, instruction)
            except RuntimeError:
                raise  # Allow RuntimeError exceptions to be thrown.
            except Exception as e:
                logger.debug("Failed to execute instruction hook with error: %s", e)

    def pre_instruction(self, context: ProcessorContext, instruction: Instruction):
        self.execute(context, instruction, pre=True)

    def post_instruction(self, context: ProcessorContext, instruction: Instruction):
        self.execute(context, instruction, pre=False)
