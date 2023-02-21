"""
Interface for variable management.
"""

from copy import deepcopy
import functools
import logging
from typing import List, Iterable, Optional

import dragodis.interface
from . import utils


logger = logging.getLogger(__name__)


class VariableMap(object):
    """
    Class that stores a set of variables that have been encountered during emulation.
    """

    def __init__(self, cpu_context):
        self._variables = {}
        self._cpu_context = cpu_context

    def __repr__(self):
        return "<VariableMap : \n\t{}\n>".format(
            "\n\t".join(([repr(var) for addr, var in sorted(self._variables.items())]))
        )

    def __deepcopy__(self, memo):
        """
        Custom implementation of deepcopy to improve efficiency.
        """
        copy = VariableMap(deepcopy(self._cpu_context, memo))
        memo[id(self)] = copy
        copy._variables = {addr: deepcopy(variable, memo) for addr, variable in list(self._variables.items())}
        return copy

    def __getitem__(self, addr_or_name) -> "Variable":
        """Gets a variable by name or address."""
        if isinstance(addr_or_name, str):
            name = addr_or_name
            for var in self:
                if name == var.name:
                    return var
            raise KeyError(f"{name} not found.")
        elif isinstance(addr_or_name, int):
            return self._variables[addr_or_name]
        else:
            raise KeyError(f"Invalid variable name or address: {addr_or_name!r}")

    def __len__(self):
        return len(self._variables)

    def get(self, addr_or_name, default=None) -> "Variable":
        """Gets a variable by name or address."""
        try:
            return self[addr_or_name]
        except (KeyError, ValueError):
            return default

    def at(self, ip) -> List["Variable"]:
        """
        Retrieves the variables referenced at the given instruction address.

        :param ip: Instruction address to get pointers from.
        :return: List of Variable objects that were found within the given instruction.

        :raises ValueError: If instruction has not been executed yet.
        """
        if ip not in self._cpu_context.executed_instructions:
            raise ValueError("Unable to get variables. Instruction at 0x{:0x} has not been executed.".format(ip))

        return [var for var in self if ip in var.references]

    def __setitem__(self, addr_or_name, variable):
        """Sets a variable by name or address."""
        if isinstance(addr_or_name, str):  # TODO
            raise NotImplementedError("Creating new variable by name is currently not supported.")
        elif isinstance(addr_or_name, int):
            self._variables[addr_or_name] = variable
        else:
            raise ValueError("Invalid variable name or address: {!r}".format(addr_or_name))

    def __contains__(self, addr_or_name) -> bool:
        if isinstance(addr_or_name, str):
            name = addr_or_name
            return any(name == var.name for var in self)
        elif isinstance(addr_or_name, int):
            addr = addr_or_name
            return addr in self._variables
        else:
            # We could have floats or None checked if dealing with a FPU register.
            return False

    def __iter__(self) -> Iterable["Variable"]:
        return iter(self._variables.values())

    def add(self, addr, variable: dragodis.interface.Variable = None, reference=None) -> "Variable":
        """
        Creates and adds a variable object to mapping by object

        If the variable already exists, this function does nothing.

        :return: Variable object that has been created or one that already exists.
        """
        if addr in self._variables:
            var = self._variables[addr]
        else:
            if not variable:
                variable = self._cpu_context.emulator.disassembler.get_variable(addr)
            var = Variable(self._cpu_context, addr, variable=variable)
            # logger.debug('VariableMap :: Created variable: {!r}'.format(var))
            self._variables[addr] = var
        if reference:
            var.add_reference(reference)
        return var

    @property
    def names(self) -> List[str]:
        return [var.name for var in self]

    @property
    def addrs(self) -> List[int]:
        return list(self._variables.keys())

    @property
    def stack_variables(self) -> List["Variable"]:
        return [var for var in self if var.is_stack]

    @property
    def global_variables(self) -> List["Variable"]:
        return [var for var in self if not var.is_stack]


@functools.total_ordering
class Variable(object):
    """
    Stores information for a local / global variable for a specific CPU context state.

    :var addr: Address of variable within current context.
    :var references: List of instruction pointers where the variables was encountered.
    """

    def __init__(self, cpu_context, addr, variable: dragodis.interface.Variable):
        self._cpu_context = cpu_context
        self._variable = variable
        self.addr = addr
        self.references = []

    def __deepcopy__(self, memo):
        copy = self.__new__(self.__class__)
        memo[id(self)] = copy
        copy._cpu_context = deepcopy(self._cpu_context, memo)
        copy._variable = self._variable
        copy.addr = self.addr
        copy.references = list(self.references)
        return copy

    def __repr__(self):
        data_type_str = self.data_type
        if self.count > 1 and data_type_str != "func_ptr":
            data_type_str += f"[{self.count}]"
        string = (
            f"<Variable {self.name} "
            f": type = {data_type_str} "
            f": addr = 0x{self.addr:0x} "
            f": value = {repr(self.value)} "
            f": size = {self.size} "
        )
        stack_offset = self.stack_offset
        if stack_offset is not None:
            string += f": stack_offset = {stack_offset} "
        string += ">"
        return string

    def __eq__(self, other):
        return self.addr == other.addr

    def __lt__(self, other):
        return self.addr < other.addr

    @property
    def is_stack(self) -> bool:
        """True if variable is on stack."""
        return bool(self._variable and isinstance(self._variable, dragodis.interface.StackVariable))

    @property
    def stack_offset(self) -> Optional[int]:
        """The offset within the stack relative to the current stack pointer."""
        if self.is_stack:
            return self.addr - self._cpu_context.sp

    @property
    def name(self):
        return self._variable.name

    @property
    def size(self):
        """Size of data"""
        return self._variable.size
    @property
    def data_type_size(self) -> int:
        """The data type size, defaults to 1 if unknown"""
        return self._variable.data_type.size

    @property
    def count(self) -> int:
        """Count of elements in the array."""
        return self.size // self.data_type_size

    @property
    def data(self) -> bytes:
        """The raw data the variable is pointing to."""
        return self._cpu_context.memory.read(self.addr, self.size)

    @data.setter
    def data(self, value: bytes):
        """Sets the raw data the variable is pointing to."""
        size = self.size
        if len(value) > size:
            raise ValueError(f"Data size for variable at 0x{self.addr:08x} ({self.name}) must be <= {size} bytes.")

        self._cpu_context.memory.write(self.addr, value)

    @property
    def data_type(self) -> str:
        """The data type as a string."""
        return self._variable.data_type.name

    def add_reference(self, ip):
        """Adds ip to list of references for this variable."""
        # Ignore duplicate calls.
        if self.references and ip == self.references[-1]:
            return
        self.references.append(ip)

    def _data_array(self) -> List[int]:
        """Returns data as an array of unpacked integers based on data_type_size."""
        data = self.data
        data_type_size = self.data_type_size
        return [
            int.from_bytes(data[i:i + data_type_size], self._cpu_context.byteorder)
            for i in range(0, len(data), data_type_size)
        ]

    @property
    def value(self):
        """The unpacked data the variable is pointing to."""
        if utils.is_func_ptr(self._cpu_context.emulator.disassembler, self.addr):
            return self.addr

        data = self.data
        data_type = self.data_type.casefold()
        is_pointer = "*" in data_type
        data_array = self._data_array()

        # Present value as bytes data_type matches.
        if not is_pointer:
            if data_type in ("string", "struct", "tbyte"):
                return data
            if "char" in data_type or "byte" in data_type:
                if len(data_array) == 1:
                    return data_array[0]
                else:
                    return data

        # Otherwise present value as an integer.
        if data_type in ("float", "double"):
            data_array = [utils.int_to_float(value) for value in data_array]

        if len(data_array) == 1:
            return data_array[0]
        return data_array

    @value.setter
    def value(self, value):
        """Set the data the variable is pointing to."""
        data_type = self.data_type.casefold()

        if data_type in ("tbyte", "string", "struct"):
            self.data = value

        width = self.data_type_size
        if isinstance(value, list):
            if data_type in ("float", "double"):
                value = [utils.float_to_int(_value) for _value in value]
            value = [_value.to_bytes(width, self._cpu_context.byteorder) for _value in value]
            self.data = b"".join(value)
        else:
            if data_type in ("float", "double"):
                value = utils.float_to_int(value)
            self.data = value.to_bytes(width, self._cpu_context.byteorder)

    @property
    def history(self):
        """The history of variables by following memory copies."""
        # (We shouldn't have Nones)
        history = []
        for addr in self._cpu_context.get_pointer_history(self.addr):
            var = self._cpu_context.variables.get(addr, None)
            if var:
                history.append(var)
        return history
