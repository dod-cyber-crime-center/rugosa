"""
Interface for operand management in x86.
"""

import logging
from typing import Optional

from dragodis import OperandType
from dragodis.interface import Phrase, MemoryReference, Immediate, Register

from .. import utils
from ..operands import Operand

logger = logging.getLogger(__name__)


class x86_64Operand(Operand):

    def _calc_displacement(self):
        """
        Calculate the displacement offset of the operand's text.

        e.g:
            word ptr [rdi+rbx]

        :return int: calculated value
        """
        addr = self.base + self.index * self.scale + self.offset
        if addr < 0:
            addr = utils.unsigned(addr, self._cpu_context.byteness)
        logger.debug(
            "Calculating operand: %s -> 0x%X + 0x%X*0x%X %s 0x%X = 0x%X" % (
                self.text,
                self.base,
                self.index,
                self.scale,
                "-" if self.offset < 0 else "+",
                abs(self.offset),
                addr
            )
        )

        return addr

    @property
    def scale(self) -> Optional[int]:
        """
        The scaling factor of the index if operand is a displacement.

        e.g.
            [ebp+ecx*2+var_8] -> 2
        """
        phrase = self._operand.value
        if not isinstance(phrase, Phrase):
            return None
        return phrase.scale

    @property
    def index(self) -> Optional[int]:
        """
        The value of the index register if operand is a displacement.
        Returns None if not a displacement.

        e.g.
            [ebp+ecx*2+var_8] -> ecx
        """
        phrase = self._operand.value
        if not isinstance(phrase, Phrase):
            return None
        index_reg = phrase.index
        if not index_reg:
            return 0
        value = self._cpu_context.registers[index_reg.name]
        return utils.signed(value, self._cpu_context.byteness)

    @property
    def offset(self) -> Optional[int]:
        """
        The offset value if the operand is a displacement.

        e.g.
            [ebp+ecx*2+8] -> 8
            fs:[eax] -> eax
        """
        phrase = self._operand.value
        if not isinstance(phrase, Phrase):
            return None
        offset = phrase.offset
        if isinstance(offset, Register):
            offset = self._cpu_context.registers[offset.name]
        return offset

    @property
    def addr(self) -> Optional[int]:
        """
        Retrieves the referenced memory address of the operand.

        :return int: Memory address or None if operand is not a memory reference.
        """
        addr = None
        value = self._operand.value
        if isinstance(value, Phrase):
            # These need to be handled in the same way even if they don't contain the same types of data...
            addr = self._calc_displacement()

        # TODO: Originally this only pulled o_mem types, but now we also do o_near/o_far
        #   Determine if that is okay.
        elif isinstance(value, (MemoryReference, Immediate)):
            addr = int(value)

        if addr is not None:
            logger.debug("&%s -> 0x%X", self.text, addr)

        return addr

    @property
    def base_addr(self):
        """
        Retrieves the referenced memory address of the operand minus any indexing that
        has occurred.

        This is useful for pulling out the un-offseted address within a loop.
        e.g. "movzx   edx, [ebp+ecx*2+var_8]"
        where ecx is the loop index starting at a non-zero value.

        :return int: Memory address or None if operand is not a memory reference.
        """
        addr = self.addr
        if addr is None:
            return None
        index = self.index
        if index is not None:
            addr -= index * self.scale
        return addr

    @property
    def value(self):
        return super().value

    @value.setter
    def value(self, value):
        try:
            logger.debug("0x%X -> %s", value, self.text)
        except TypeError:
            logger.debug("%r -> %s", value, self.text)

        # On 64-bit, the destination register must be set to 0 first (per documentation)
        # TODO: Check if this happens regardless of the source size
        if (
                self.type == OperandType.register
                and self._cpu_context.bitness == 64
                and self.width == 4
        ):  # Only do this for 32-bit setting
            reg_name = self._operand.value.name.lower()
            self._cpu_context.registers.clear_family(reg_name)

        super(x86_64Operand, self.__class__).value.__set__(self, value)
