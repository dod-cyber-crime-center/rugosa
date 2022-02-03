"""
Interface for operand management.
"""

from __future__ import annotations
import collections
import logging
from copy import deepcopy
from typing import TYPE_CHECKING, Optional, Union

# TODO: Should dragodis have it's interface in the root module?
import dragodis.interface
from dragodis import OperandType
from dragodis.interface import Phrase, Immediate, Register, MemoryReference

from . import utils
from .exceptions import EmulationError

if TYPE_CHECKING:
    from .cpu_context import ProcessorContext


logger = logging.getLogger(__name__)


class Operand:
    """
    Stores information for a given operand for a specific CPU context state.
    Wraps a dragodis Operand object in order to provide dynamic information
    for the operand based on the attached processor context.
    """

    def __init__(self, cpu_context: ProcessorContext, operand: dragodis.interface.Operand):
        """
        :param cpu_context: CPU context to pull operand value
        :param operand: dragodis Operand object to wrap.
        """
        self._cpu_context = cpu_context
        self._operand = operand

    def __repr__(self):
        string = f"<{self.__class__.__name__} 0x{self.ip:0x}:{self.idx} : {self.text} = {self.value!r}"
        if self.addr is not None:
            string += f" : &{self.text} = 0x{self.addr:0x}"
        string += f" : width = {self.width}>"
        return string

    def __deepcopy__(self, memo):
        # When we deep copy, clear out the __insn attribute so we don't
        # run into any serialization issues with Swig objects.
        deepcopy_method = self.__deepcopy__
        self.__deepcopy__ = None
        self.__insn = None
        copy = deepcopy(self, memo)
        self.__deepcopy__ = deepcopy_method
        return copy

    @property
    def ip(self) -> int:
        return self._operand.address

    @property
    def idx(self) -> int:
        return self._operand.index

    # TODO: Update those that use this attribute.
    @property
    def type(self) -> dragodis.interface.OperandType:
        return self._operand.type

    @property
    def text(self) -> str:
        return self._operand.text

    def _record_address_variable(self, addr: int):
        """
        Record the reference to the address if address is a defined variable.
        """
        if addr in self._cpu_context.variables:
            self._cpu_context.variables[addr].add_reference(self.ip)

    @property
    def width(self):
        """
        Based on the dtype value, the size of the operand in bytes

        :return: size of data type
        """
        return self._operand.width

    @property
    def is_hidden(self):
        """
        True if the operand is not part of the visible assembly code.
        (These are for implicit registers like EAX)
        """
        return self._operand.text == "" or self._operand.type == OperandType.void

    @property
    def is_func_ptr(self):
        """True if the operand is a pointer to a function."""
        return utils.is_func_ptr(self._cpu_context.emulator.disassembler, self.addr or self.value)

    @property
    def offset(self) -> Optional[int]:
        """The offset value if the operand is a displacement."""
        return None

    @property
    def base(self) -> Optional[int]:
        """The value of the base register if operand is a displacement."""
        phrase = self._operand.value
        if not isinstance(phrase, Phrase):
            return None
        base_reg = phrase.base
        if not base_reg:
            return 0
        value = self._cpu_context.registers[base_reg.name]
        return utils.signed(value, self._cpu_context.byteness)

    @base.setter
    def base(self, value: int):
        """Sets the value of the base register if operand is a displacement."""
        phrase = self._operand.value
        if isinstance(phrase, Phrase):
            self._cpu_context.registers[phrase.base.name] = value

    @property
    def addr(self) -> Optional[int]:
        """
        Retrieves the referenced memory address of the operand.

        This should be overwritten by architecture specific Operand implementations
        if this property is applicable.

        :return int: Memory address or None if operand is not a memory reference.
        """
        return None

    @property
    def value(self) -> Union[None, int, bytes]:
        """
        Retrieve the value of the operand as it is currently in the cpu_context.
        NOTE: We can't cache this value because the value may change based on the cpu context.

        :return int: An integer or byes of the operand value.
        """
        if self.is_hidden:
            return None

        value = self._operand.value

        if isinstance(value, Immediate):
            return int(value)

        # Record reference if address is a variable address and memory reference.
        # operand is one of o_near, o_far, o_mem
        if isinstance(value, MemoryReference) and self._operand.type == OperandType.code:
            addr = int(value)
            self._record_address_variable(addr)
            return addr

        if isinstance(value, Register):
            value = self._cpu_context.registers[value.name]
            self._record_address_variable(value)
            return value

        if isinstance(value, (Phrase, MemoryReference)):
            addr = self.addr
            self._record_address_variable(addr)

            # If a function pointer, we want to return the address.
            # This is because a function may be seen as a memory reference, but we don't
            # want to dereference it in case it in a non-call instruction.
            # (e.g.  "mov  esi, ds:LoadLibraryA")
            # NOTE: Must use internal function to avoid recursive loop.
            if utils.is_func_ptr(self._cpu_context.emulator.disassembler, addr):
                return addr

            # Return empty
            if not self.width:
                logger.debug("Width is zero for %s, returning empty string.", self.text)
                return b""

            # Otherwise, dereference the address.
            value = self._cpu_context.memory.read(addr, self.width)
            return int.from_bytes(value, self._cpu_context.byteorder)

        raise EmulationError(f"Invalid operand type: {self.type}", ip=self.ip)

    @value.setter
    def value(self, value: Union[int, bytes]):
        """
        Set the operand to the specified value within the cpu_context.
        """
        # Value may be signed.
        if isinstance(value, int) and value < 0:
            value = utils.unsigned(value, self.width * 8)

        # If we are writing to an immediate, I believe they want to write to the memory at the immediate.
        # TODO: Should we fail instead?
        if self.type == OperandType.immediate:
            offset = self.value
            line = self._cpu_context.emulator.disassembler.get_line(offset)
            if line.is_loaded:
                self._cpu_context.memory.write(offset, value)
            return

        if self.type == OperandType.register:
            # Convert the value from string to integer...
            if isinstance(value, str):
                value = int.from_bytes(value, self._cpu_context.byteorder)
            reg = self._operand.value
            self._cpu_context.registers[reg.name] = value
            return

        if self.type in (OperandType.memory, OperandType.phrase):
            if isinstance(value, int):
                value = value.to_bytes(self.width, self._cpu_context.byteorder)
            self._cpu_context.memory.write(self.addr, value)
            return

        raise EmulationError(f"Invalid operand type: {self.type}", ip=self.ip)


# This is a "lite" version of the Operand class that only allows access only to a few attributes, is read only,
# and not backed by a CPU context.
OperandLite = collections.namedtuple("OperandLite", "ip idx text value")
