"""
Interface for function management.
"""
from __future__ import annotations

from typing import List

import logging

import dragodis.interface
from dragodis import Disassembler, NotExistError
from dragodis.interface import (
    StackLocation, RelativeRegisterLocation, StaticLocation, RegisterLocation,
    RegisterPairLocation
)

from . import utils

logger = logging.getLogger(__name__)


class FunctionSignature:
    """
    Interface for a function signature.

    NOTE: This object retrieves the signature on initialization.
    Any external changes to the function's signature after this object is created will take
    no affect.
    As well, any changes done to this object will not affect the signature in the IDB unless
    the apply() function is called.
    """

    def __init__(self, cpu_context, address: int, signature: dragodis.interface.FunctionSignature):
        """
        :param cpu_context: ProcessorContext to use for pulling argument values.
        :param address: Address of function for this signature.
        :param signature: dragodis FunctionSignature to wrap.
        """
        self._cpu_context = cpu_context
        self._signature = signature
        self.address = address

    def __repr__(self):
        return f'< FunctionSignature : {self.declaration} >'

    @property
    def name(self) -> str:
        """The demangled name of function."""
        return self._signature.name

    @property
    def declaration(self) -> str:
        """The full function declaration."""
        return self._signature.declaration

    @property
    def arguments(self) -> List[FunctionArgument]:
        """
        Gets the defined arguments for the function signature.
        NOTE: We name this argument instead of parameters since it is based on an
        underlying context for a specific value.
        """
        return [
            FunctionArgument(self._cpu_context, self, parameter)
            for parameter in self._signature.parameters
        ]

    def remove_argument(self, ordinal: int):
        self._signature.remove_parameter(ordinal)

    def add_argument(self, data_type: str):
        self._signature.add_parameter(data_type)

    def insert_argument(self, ordinal: int, data_type: str):
        self._signature.insert_parameter(ordinal, data_type)


class FunctionArgument:
    """
    Interface for a function argument from FunctionSignature
    """

    def __init__(self, cpu_context, signature: FunctionSignature, parameter: dragodis.interface.FunctionParameter):
        self._cpu_context = cpu_context
        self._signature = signature
        self._parameter = parameter

    def __repr__(self):
        string = (
            f"< FunctionArg {hex(self._signature.address)}:{self.ordinal} "
            f": {self.declaration} = {hex(self.value)}"
        )
        if self.addr is not None:
            string += f" : &{self.name} = {hex(self.addr)}"
        string += " >"
        return string

    @property
    def ordinal(self) -> int:
        return self._parameter.ordinal

    @property
    def width(self) -> int:
        return self._parameter.size

    @property
    def name(self) -> str:
        return self._parameter.name

    @name.setter
    def name(self, value: str):
        self._parameter.name = value

    @property
    def type(self) -> str:
        """User friendly type name."""
        return self._parameter.data_type.name

    @type.setter
    def type(self, value: str):
        """
        Sets function argument to a new type.
        """
        # TODO: Should modifying the data type affect the signature itself?
        self._parameter.data_type = value

    @property
    def declaration(self):
        """Argument type declaration."""
        return self._parameter.declaration

    @property
    def is_stack(self):
        """True if argument is on the stack."""
        return isinstance(self._parameter.location, StackLocation)

    # TODO: Refactor to be more processor agnostic
    @property
    def addr(self):
        """Retrieves the address of the argument (if a memory/stack address)"""
        location = self._parameter.location
        disassembler: Disassembler = self._cpu_context.emulator.disassembler

        if isinstance(location, StackLocation):
            # First get the offsetted stack location.
            addr = self._cpu_context.sp + location.stack_offset

            try:
                func = disassembler.get_function(self._signature.address)
                in_function = self._cpu_context.ip in func
            except NotExistError:
                in_function = False

            if disassembler.processor_name == "x86":
                # If we are inside the calling function (or in the middle of hooking a call)
                # account for the pushed in return address.
                if in_function or self._cpu_context.hooking_call == self._signature.address:
                    # Determine adjustment of stack based on what IDA reports as the current
                    # ESP plus the size of the saved return address.
                    # (More reliable and cross compatible than using ebp.)
                    retaddr_size = self._cpu_context.byteness
                    addr += retaddr_size

            # Also adjust the stack if we are in the function.
            if in_function:
                instruction = disassembler.get_instruction(self._cpu_context.ip)
                addr -= instruction.stack_depth  # this is negative

            return addr

        if isinstance(location, StaticLocation):
            return location.address

        return None

    @property
    def value(self):
        """Retrieves the value of the argument based on the cpu context."""
        # TODO: Pull value data based on type.
        location = self._parameter.location

        # On Stack
        if isinstance(location, StackLocation):
            logger.debug(
                f"Retrieving argument {self.ordinal} at {hex(self.addr)}, "
                f"stack: {hex(self._cpu_context.sp)}, offset: {hex(location.stack_offset)}"
            )
            # read the argument from teh stack using the calculated stack offset from the disassembler.
            value = self._cpu_context.memory.read(self.addr, self._cpu_context.byteness)
            return int.from_bytes(value, self._cpu_context.byteorder)

        # Single register
        if isinstance(location, RegisterLocation):
            return self._cpu_context.registers[location.register.name]

        # Register pair (eg: edx:eax)
        if isinstance(location, RegisterPairLocation):
            # Width is the combination of both registers.
            reg_width = self.width // 2
            reg1, reg2 = location.registers
            logger.debug("Register pair: [%s:%s]", reg1.name, reg2.name)
            reg1_value = self._cpu_context.registers[reg1.name]
            reg2_value = self._cpu_context.registers[reg2.name]
            return (reg2_value << (reg_width * 8)) | reg1_value

        # Relative register (displacement from address pointed by register)
        if isinstance(location, RelativeRegisterLocation):
            # TODO: CURRENTLY UNTESTED
            logger.info(
                f"Argument {self.ordinal} of untested type ALOC_RREL.  "
                f"Verify results and report issues."
            )
            return self._cpu_context.registers[location.register.name] + location.offset

        # Global address
        if isinstance(location, StaticLocation):
            return location.address

        raise NotImplementedError(f"Unsupported location: {location!r}")

    @value.setter
    def value(self, value):
        """Sets the value of the argument to the cpu context."""
        # TODO: Pull value data based on type.
        location = self._parameter.location

        # On Stack
        if isinstance(location, StackLocation):
            logger.debug(
                f"Setting argument {self.ordinal} at {hex(self.addr)}, "
                f"stack: {hex(self._cpu_context.sp)}, offset: {hex(location.stack_offset)}"
            )
            data = value.to_bytes(self._cpu_context.byteness, self._cpu_context.byteorder)
            self._cpu_context.memory.write(self.addr, data)

        # Single register
        elif isinstance(location, RegisterLocation):
            self._cpu_context.registers[location.register.name] = value

        # Register pair (eg: edx:eax)
        elif isinstance(location, RegisterPairLocation):
            reg_width = self.width // 2
            reg1, reg2 = location.registers
            self._cpu_context.registers[reg1.name] = value & utils.get_mask(reg_width)
            self._cpu_context.registers[reg2.name] = value >> (reg_width * 8)

        # Relative register (displacement from address pointed by register)
        elif isinstance(location, RelativeRegisterLocation):
            # TODO: CURRENTLY UNTESTED
            logger.info(
                f"Argument {self.ordinal} of untested type ALOC_RREL.  "
                r"Verify results and report issues."
            )
            self._cpu_context.registers[location.register.name] = value - location.offset

        # Global address
        elif isinstance(location, StaticLocation):
            raise TypeError(f"Unable to set a argument {self.ordinal} with a static location.")

        else:
            raise NotImplementedError(f"Unsupported location: {location!r}")
