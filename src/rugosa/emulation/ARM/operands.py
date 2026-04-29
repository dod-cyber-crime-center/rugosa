"""
Interface for operand management in ARM.
"""

import logging
from typing import Optional, List

from dragodis.interface import Register, Phrase, MemoryReference, RegisterList
from dragodis.interface.types import ARMShiftType, OperandType

from ..operands import Operand
from ..exceptions import EmulationError
from .. import utils
from . import utils as arm_utils

logger = logging.getLogger(__name__)


class ARMOperand(Operand):

    _shift_map = {
        ARMShiftType.LSL: arm_utils.lsl,
        ARMShiftType.LSR: arm_utils.lsr,
        ARMShiftType.ASR: arm_utils.asr,
        ARMShiftType.ROR: arm_utils.ror,
        # rrx requires also passing in carry. (see usage)
        # TODO: Support other shift operations.
        ARMShiftType.UXTX: arm_utils.lsl
    }

    @property
    def offset(self) -> Optional[int]:
        """The offset value if the operand is a displacement/phrase."""
        phrase = self._operand.value
        if not isinstance(phrase, Phrase) or phrase.offset is None:
            return None

        offset = phrase.offset

        # Offset is a register.
        # [R1, R2]
        if isinstance(offset, Register):
            offset = self._cpu_context.registers[offset.name]
            # We could also have a shift applied in the offset.
            #   [R1, R2, LSL #3]
            offset = self._calc_shift(offset)
            offset = utils.signed(offset, self._cpu_context.bitness)

        # Otherwise offset is an immediate.
        # [R1, #1]

        return offset

    @property
    def shift_count(self) -> int:
        """The amount to shift (if a shifted register)"""
        _, shift_count = self._operand.shift
        if isinstance(shift_count, Register):
            shift_count = self._cpu_context.registers[shift_count.name]
        return shift_count

    def _calc_shift(self, value) -> int:
        """
        Calculates the shift applied within the operand.
        This could be applied directly or within the offset of a displacement.
            e.g.
                R2, LSL #3 -> R2 << 3
                R2, LSL R3 -> R2 << R3
                [R1, R2, LSL #3]  -> R2 << 3

        NOTE: Any modifications to the carry flag will be applied only if
             the condition flag is set and the context's ip is the same as the
             address of the operand's instruction.

        :param value: The base value the shift is to be applied to.
        :return: Results of the shift (or original value back if no shift is applicable.)
        """
        count = self.shift_count
        if count > 0:
            shift_op, _ = self._operand.shift
            if shift_op == ARMShiftType.RRX:  # RRX also requires original carry flag
                carry, value = arm_utils.rrx(self._cpu_context.registers.c, value, count)
            else:
                carry, value = self._shift_map[shift_op](value, count)

            # Update carry flag if condition flag is set for instruction (S postfix)
            # (But only update if context's instruction pointer is still looking at this instruction.)
            if self._operand.instruction.update_flags and self._cpu_context.ip == self.ip:
                self._cpu_context.registers.c = carry

        return value

    @property
    def addr(self) -> Optional[int]:
        """
        The referenced memory address of the operand.
        :return int: Memory address or None if operand is not a memory reference.
        """
        addr = None
        value = self._operand.value

        if isinstance(value, Phrase):
            addr = self.base

            # Ignore including the offset if post indexed.
            #   ie. include offset for [R2, #4] but ignore for [R2], #4
            if not self._operand.instruction.post_indexed:
                offset = self.offset
                logger.debug("0x%X + 0x%X = 0x%X", addr, offset, addr + offset)
                addr += offset

            if addr < 0:
                logger.debug("Address is negative, resorting to address of 0.")
                addr = 0

        elif isinstance(value, MemoryReference):
            addr = int(value)

        if addr is not None:
            logger.debug("&%s -> 0x%X", self.text, addr)

        return addr

    @property
    def is_signed(self) -> bool:
        """
        Whether the memory addressing is signed.
        """
        mnem = self._operand.instruction.mnemonic
        return any(suffix in mnem for suffix in ["sb", "sh", "sw"])

    @property
    def register_list(self) -> Optional[List[str]]:
        """
        List of register names if operand is a register list.
        """
        reg_list = self._operand.value
        if not isinstance(reg_list, RegisterList):
            return None
        return [reg.name for reg in reg_list]

    @property
    def value(self):
        value = self._operand.value

        # Barrel shifter
        if isinstance(value, Register):
            value = self._cpu_context.registers[value.name]
            # Run _calc_shift to handle barrel shifter.
            # (Shift won't occur if shift count is 0)
            value = self._calc_shift(value)
            self._record_address_variable(value)
            return value

        # Register list
        if isinstance(value, RegisterList):
            return [self._cpu_context.registers[reg.name] for reg in value]

        value = super().value

        # If a memory reference, the final value may be signed.
        if isinstance(value, (MemoryReference, Phrase)) and self.is_signed:
            value = utils.signed(value, self._cpu_context.byteness)

        return value

    @value.setter
    def value(self, value):
        try:
            logger.debug("0x%X -> %s", value, self.text)
        except TypeError:
            logger.debug("%r -> %s", value, self.text)

        # Barrel shifter
        if self.type == OperandType.register and self.shift_count:
            raise EmulationError(f"Unable to set value to operand with a shift", ip=self.ip)

        # Register list
        reg_list = self.register_list
        if reg_list:
            # To set the value for an operand that is a register list, user must provide
            # a list of value of equal size.
            # User can use None to indicate not to update that register.
            if not isinstance(value, list) or len(value) != len(reg_list):
                raise ValueError(f"Operand value for {self.text} must be a list of {len(reg_list)} values.")
            for reg_name, reg_value in zip(reg_list, value):
                if reg_value is not None:
                    self._cpu_context.registers[reg_name] = reg_value
            return

        super(ARMOperand, self.__class__).value.__set__(self, value)
