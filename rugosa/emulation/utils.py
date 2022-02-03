"""
This file contains utility functions utilized throughout the emulation package.
"""
from __future__ import annotations

import logging
import re
import struct

from dragodis import Disassembler, NotExistError
from .exceptions import EmulationError


logger = logging.getLogger(__name__)


def signed(n: int, size: int) -> int:
    """
    Convert an unsigned integer to a signed integer

    :param uint n: value to convert
    :param int size: byte width of n

    :return int: signed conversion
    """
    size *= 8
    if n >> (size - 1):  # Is the hi-bit set?
        return n - (1 << size)
    return n


def unsigned(n: int, size: int) -> int:
    """
    Convert a signed integer to an unsigned integer

    :param sint n: value to convert
    :param in size: byte width of n
        Defaults to architecture addressing size.

    :return int: unsigned conversion
    """
    size *= 8
    return n & ((1 << size) - 1)


def sign_bit(value: int, size: int) -> int:
    """Returns the highest bit with given value and byte width."""
    return (value >> ((8 * size) - 1)) & 0x1


def sign_extend(value: int, orig_size: int, dest_size: int) -> int:
    """
    Calculates the sign extension for a provided value and a specified destination size.

    :param value: value to be sign extended
    :param orig_size: byte width of value
    :param dest_size: byte width of value to extend to.
    :return: value, sign extended
    """
    if dest_size < orig_size:
        raise ValueError(f"Destination size must be larger than original size.")
    orig_size *= 8
    dest_size *= 8

    # Calculate the max value for orig and dest
    orig_mask = (1 << orig_size) - 1
    dest_mask = (1 << dest_size) - 1
    # Create the bit mask
    masknumber = value & orig_mask
    msb = masknumber >> (orig_size - 1)
    # Perform the sign extension
    if msb:
        signextended = ((dest_mask << orig_size) | masknumber) & dest_mask
    else:
        signextended = value & dest_mask

    return signextended


def float_to_int(value: float, precision: int = 2) -> int:
    """
    Given a float value, convert it to its integer hexadecimal equivalent.

    >>> float_to_int(1.0)
    >>> 4607182418800017408

    :param value: float to convert to int equivalent
    :param precision: single or double precision (1 for single, 2 for double)
    :return: int
    :raises: ValueError
    """
    if precision == 1:
        return struct.unpack("H", struct.pack("f", value))[0]
    elif precision == 2:
        return struct.unpack("Q", struct.pack("d", value))[0]
    else:
        raise EmulationError(f"Precision {precision} is not valid.")


def int_to_float(value: int, precision: int = 2) -> float:
    """
    Given an integer value, convert it to its float hexadecimal equivalent.

    >>> int_to_float(4607182418800017408, 8)
    >>> 1.0

    :param int value: integer value to convert to float equivalent
    :param int precision: single or double precision
    :return: int or None
    :raises: ValueError
    """
    if precision == 1:
        return struct.unpack("f", struct.pack("H", value))[0]
    elif precision == 2:
        return struct.unpack("d", struct.pack("Q", value))[0]
    else:
        raise EmulationError(f"Precision {precision} is not valid.")


def get_mask(size: int) -> int:
    """
    Get bit mask based on byte size.

    :param size: number of bytes to obtain mask for

    :return: mask of width size
    """
    return (1 << (8 * size)) - 1


def sanitize_func_name(func_name: str) -> str:
    """Sanitizes the IDA function names to it's core name."""
    # remove the extra "_" IDA likes to add to the function name.
    if func_name.startswith("_"):
        func_name = func_name[1:]

    # Remove the numbered suffix IDA likes to add to duplicate function names.
    func_name = re.sub("_[0-9]+$", "", func_name)

    return func_name


def is_func_ptr(dis: Disassembler, address: int) -> bool:
    """Returns true if the given offset is a function pointer."""
    # As a first check, simply see if the offset is the start of a function.
    try:
        func = dis.get_function(address)
        if func.start == address:
            return True
    except NotExistError:
        pass

    # Next determine if we can successfully get a function signature.
    # TODO: Determine if there is a way to do this without calling get_function_signature()
    #   (Optimization)
    try:
        func_sig = dis.get_function_signature(address)
        return True
    except NotExistError:
        pass

    return False
