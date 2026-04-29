"""
Contains the base classes for Monitor.
"""
from __future__ import annotations
from typing import  Callable, TypedDict, Unpack

from rugosa.emulation.cpu_context import ProcessorContext
from rugosa.emulation.instruction import Instruction


__all__ = [
    "Monitor",
    "ScopedMonitor",
    "CallbacksMonitor"
]


class Monitor:

    def pre_instruction(self, context: ProcessorContext, instruction: Instruction):
        """This hook is called before an instruction is executed."""

    def post_instruction(self, context: ProcessorContext, instruction: Instruction):
        """This hook is called after an instruction is executed."""

    def block_start(self, context: ProcessorContext, instruction: Instruction):
        """This hook is called before the first instruction of a block is executed."""

    def block_end(self, context: ProcessorContext, instruction: Instruction):
        """This hook is called after the last instruction of a block is executed."""

    def function_start(self, context: ProcessorContext, instruction: Instruction):
        """This hook is called before the first instruction of a function is executed."""

    def function_end(self, context: ProcessorContext, instruction: Instruction):
        """This hook is called after the last instruction of a function is executed."""

    def code_path_end(self, context: ProcessorContext, instruction: Instruction):
        """
        This hook is called after the last instruction of a functional code path is complete.
        NOTE: This is different to function_end() in that we could end in the middle of a function
        if the next block will lead us into a loop, and we aren't following loops.
        """

    # TODO: Add things like pre_call/post_call, pre_memory_write/post_memory_write, etc.

Callback = Callable[[ProcessorContext, Instruction], None]


class CallbacksMonitor(Monitor):
    """
    Helper monitor used with user provided callback methods.
    Prevents the need for creating a class for a one-off monitor.
    Used with the keyword arguments of emu.monitor()
    """

    class Args(TypedDict, total=False):
        pre_instruction: Callback
        post_instruction: Callback
        block_start: Callback
        block_end: Callback
        function_start: Callback
        function_end: Callback
        code_path_end: Callback


    def __init__(self, **kwargs: Unpack[Args]):
        for name, callback in kwargs.items():
            setattr(self, name, callback)


class ScopedMonitor(Monitor):

    def __init__(self, scope="instruction"):
        self.scope = scope
        if scope == "function":
            self.function_end = self.hook
        elif scope == "block":
            self.block_end = self.hook
        elif scope == "instruction":
            self.post_instruction = self.hook
        elif scope == "code_path":
            self.code_path_end = self.hook
        else:
            raise ValueError(f"Invalid scope: {scope}")

    def hook(self, context: ProcessorContext, instruction: Instruction):
        """This hook gets called, dependent on dynamically provided scope."""

