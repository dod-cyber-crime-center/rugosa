"""
Components for emulating an ARM architecture.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from .instruction import ARMInstruction
from ..cpu_context import ProcessorContext
from .registers import ARM_Registers
from .opcodes import OPCODES
from rugosa.config import settings

if TYPE_CHECKING:
    from rugosa.emulation.emulator import Emulator, MemoryArgs


class ARMProcessorContext(ProcessorContext):
    """Processor context for ARM architecture"""

    OPCODES = OPCODES.copy()
    _instruction_class = ARMInstruction

    def __init__(self, emulator: Emulator, memory_settings: MemoryArgs):
        bit_size = emulator.disassembler.bit_size
        super().__init__(
            emulator,
            ARM_Registers(bit_size),
            instruction_pointer="pc",
            stack_pointer="sp",
            return_register="x0",  # TODO: Specify r0 or x0 based on bitness?
            memory_settings=memory_settings
        )
        stack_base = memory_settings.get("stack_base", settings.memory.stack_base)
        sp_offset = memory_settings.get("stack_offset", settings.memory.stack_offset)
        fp_offset = memory_settings.get("base_offset", settings.memory.base_offset)

        # Set up the stack before we go.
        self.registers.sp = stack_base - sp_offset
        if bit_size == 64:
            self.registers.x29 = stack_base - fp_offset
        else:
            self.registers.r11 = stack_base - fp_offset
