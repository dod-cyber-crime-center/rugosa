"""
Interface for creating register families.
"""

from copy import deepcopy
from typing import Iterable, Optional


class Register:
    """
    Provides access to a register family.

    :param size int: size of register in bytes
    :param **masks: maps member names to a mask of the register value it corresponds to.

    >>> reg = Register(8, rax=0xFFFFFFFFFFFFFFFF, eax=0xFFFFFFFF, ax=0xFFFF, al=0xFF, ah=0xFF00)
    >>> reg.rax
    0
    >>> reg.ax
    0
    >>> reg.ah = 0x23
    >>> reg.ah
    0x23
    >>> reg.ax
    0x2300
    >>> reg.eax
    0x00002300
    >>> reg.eax = 0x123
    >>> reg.al
    0x23
    >>> reg.ah
    0x01
    >>> reg.rax
    0x0000000000000123
    """

    def __init__(self, size, family_name: str = None, **masks):
        # We are modifying self.__dict__ directly to avoid triggering the
        # overwritten __setattr__()
        self_dict = self.__dict__
        self_dict["size"] = size
        size_mask = 2 ** (8 * size) - 1
        self_dict["_size_mask"] = size_mask
        self_dict["_value"] = 0

        _masks = {}
        for name, mask in list(masks.items()):
            # Set name as family name if mask matches size.
            if not family_name and mask == size_mask:
                family_name = name
            # Get position of rightmost set bit in mask
            shift = 0
            if mask:
                _mask = mask
                while not _mask & 0x1:
                    _mask >>= 1
                    shift += 1
            _masks[name.lower()] = (mask, shift)
        self_dict["_masks"] = _masks
        self_dict["family_name"] = family_name or f"<{','.join(self.names)}>"

    def __deepcopy__(self, memo):
        copy = self.__new__(self.__class__)
        memo[id(self)] = copy
        copy_dict = copy.__dict__
        copy_dict["size"] = self.size
        copy_dict["_size_mask"] = self._size_mask
        copy_dict["_value"] = self._value
        copy_dict["_masks"] = dict(self._masks)
        copy_dict["family_name"] = self.family_name
        return copy

    def __getattr__(self, reg_name):
        try:
            mask, shift = self._masks[reg_name]
        except KeyError:
            raise AttributeError(f"Invalid register name: {reg_name}")
        return (self._value & mask) >> shift

    def __getitem__(self, reg_name):
        return self.__getattr__(reg_name)

    def __setattr__(self, reg_name, value):
        try:
            mask, shift = self._masks[reg_name]
        except KeyError:
            raise AttributeError(f"Invalid register name: {reg_name}")
        if not isinstance(value, int):
            raise ValueError(f"Register value must be int or long, got {type(value)}")
        self.__dict__["_value"] = (self._value & (mask ^ self._size_mask)) | ((value & (mask >> shift)) << shift)

    def __setitem__(self, reg_name, value):
        self.__setattr__(reg_name, value)

    def __contains__(self, reg_name):
        return reg_name in self._masks

    @property
    def names(self):
        return list(self._masks.keys())

    def clear(self):
        self.__dict__["_value"] = 0


class RegisterMap:
    """
    Holds register families and allows for direct access.

    This class contains all the CPU registers.  It is updated by both the CPU class, which
    updates the main CPU registers and the Processor class, which will update FLAGS.
    """

    def __init__(self, registers):
        """
        :param registers: list of Register instances
        """
        self_dict = self.__dict__
        self_dict["_registers"] = registers
        self_dict["_reg_map"] = self._build_reg_map(registers)

    def __iter__(self) -> Iterable[Register]:
        """Iterates the underlying registers."""
        yield from self._registers

    @staticmethod
    def _build_reg_map(registers):
        """Builds and returns a dictionary mapping register names to their respective Register object."""
        # Build a hash table mapping member names to registers.
        # (This also validates that we have no collisions while we are at it.)
        reg_map = {}
        for register in registers:
            for name in register.names:
                if name in reg_map:
                    raise RuntimeError(f"Duplicate register name: {name}")
                reg_map[name] = register
        return reg_map

    def __deepcopy__(self, memo):
        copy = self.__new__(self.__class__)
        memo[id(self)] = copy

        copy_dict = copy.__dict__
        copy_dict["_registers"] = [deepcopy(reg, memo) for reg in self._registers]
        copy_dict["_reg_map"] = self._build_reg_map(copy._registers)

        return copy

    def __getattr__(self, reg_name):
        try:
            register = self._reg_map[reg_name]
        except KeyError:
            raise AttributeError(f"Invalid register: {reg_name}")
        return register[reg_name]

    def __getitem__(self, reg_name):
        return self.__getattr__(reg_name.lower())

    def __setattr__(self, reg_name, value):
        try:
            register = self._reg_map[reg_name]
        except KeyError:
            raise AttributeError(f"Invalid register: {reg_name}")
        register[reg_name] = value

    def __setitem__(self, reg_name, value):
        self.__setattr__(reg_name.lower(), value)

    @property
    def names(self):
        return list(self._reg_map.keys())

    def clear_family(self, reg_name):
        """
        Zeros out the entire register for a given name.
        Name can be any register within a family.
        """
        try:
            register = self._reg_map[reg_name.lower()]
        except KeyError:
            raise ValueError(f"Invalid register: {reg_name}")
        register.clear()
