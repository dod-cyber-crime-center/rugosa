"""
Components for emulating an x86/x64 architecture.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from .instruction import x86_64Instruction
from ..cpu_context import ProcessorContext
from .registers import x86_64_Registers
from .opcodes import OPCODES
from . import fpu_opcodes  # trigger registration
from rugosa.config import settings

if TYPE_CHECKING:
    from rugosa.emulation.emulator import Emulator, MemoryArgs


class x86_64ProcessorContext(ProcessorContext):
    """Processor context for x86/x64 architecture"""

    OPCODES = OPCODES.copy()
    _instruction_class = x86_64Instruction

    def __init__(self, emulator: Emulator, memory_settings: MemoryArgs):
        super().__init__(
            emulator,
            registers=x86_64_Registers(),
            instruction_pointer="rip",
            stack_pointer="rsp",
            return_register="rax",
            memory_settings=memory_settings,
        )
        stack_base = memory_settings.get("stack_base", settings.memory.stack_base)
        rsp_offset = memory_settings.get("stack_offset", settings.memory.stack_offset)
        rbp_offset = memory_settings.get("base_offset", settings.memory.base_offset)

        # Set up the stack before we go.
        self.registers.rsp = stack_base - rsp_offset
        self.registers.rbp = stack_base - rbp_offset
