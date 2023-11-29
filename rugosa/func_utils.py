"""
Helper utilities for functions.
"""
import collections
from functools import lru_cache
import logging
import warnings
from typing import Iterable, Optional, List

import dragodis
from dragodis.interface import Function, LineType

__all__ = [
    "from_name",
    "api_calls",
    "create_function",
    "find_start_bounds",
    "cant_create_function",
]

logger = logging.getLogger(__name__)


def from_name(dis: dragodis.Disassembler, func_name: str, ignore_underscore: bool = False) -> Function:
    warnings.warn(
        "func_utils.from_name() is deprecated. Please use Disassembler.get_function_by_name() instead.",
        DeprecationWarning
    )
    try:
        return dis.get_function_by_name(func_name, ignore_underscore=ignore_underscore)
    except dragodis.NotExistError as e:
        raise ValueError(str(e))


@property
def api_calls(function: Function) -> collections.Counter:
    """
    Returns counter containing API calls and the number of times they were called.

    e.g.
        with dragodis.open_program("input.exe") as dis:
            func = dis.get_function(0x40000)
            api_calls = functions.api_calls(func)

    """
    return collections.Counter(callee.name for callee in function.callees)


# _PRE_PATTERNS based on priority
_X86_PRE_PATTERNS = [
    (1, b"\x55"),  # push ebp
    (2, (
        b"\x54",    # push esp
        b"\x56",    # push esi
        b"\x57",    # push edi
    ))
]


@lru_cache
def _calc_most_common_start_bytes(dis: dragodis.Disassembler) -> bytes:
    """
    Iterate over all non-lib functions and record their first instruction.
    Return the bytes for whichever instruction appears most.
    """
    counts = collections.Counter()
    for func in dis.functions():
        if not func.is_library:
            start_instruction = dis.get_instruction(func.start)
            counts.update((start_instruction.data,))
    return counts.most_common(1)[0][0]


def find_start_bounds(dis: dragodis.Disassembler, addr: int) -> List[int]:
    """
    Finds possible start bounds for a function containing ``addr``
    """
    # First look for most common start instruction and make that the highest priority.
    patterns = [(0, _calc_most_common_start_bytes(dis))]

    # Add well known start instructions based on architecture.
    if dis.processor_name == "x86":
        patterns.extend(_X86_PRE_PATTERNS)

    patterns.sort()

    findings = []
    segment = dis.get_segment(addr)
    for line in segment.lines(start=addr, reverse=True):
        # A function or an alignment byte stops search.
        if dis.get_function(line.address, None) or line.type == LineType.align:
            break
        data = line.data
        for priority, pattern in patterns:
            if data.startswith(pattern):
                findings.append((priority, line.address))
                break

    # Return findings sorted by priority and address (top-down)
    return [address for _, address in sorted(findings)]


def cant_create_function(dis: dragodis.Disassembler, addr: int) -> bool:
    """
    Checks for a few conditions at the provided address.  If any of these conditions are
    met, we either can't create a function at the provided address or we don't want to.
    """
    line = dis.get_line(addr, None)
    if not line:
        return True

    if not dis.get_segment(addr, None):
        return True

    if line.type == LineType.align:
        logger.warning(f"Can't create a function containing an alignment byte. address: {hex(addr)}")
        return True

    # Yes, the nop bit may be incorrect, but it's gonna be a very special case that needs a function with nops
    if line.data == b"\x90":
        logger.warning(f"Can't create a function containing a nop. address: {hex(addr)}")
        return True

    return False


def create_function(dis: dragodis.Disassembler, addr: int) -> Optional[Function]:
    """
    Attempts to create a function containing given address.

    :param dis: Dragodis disassembler object.
    :param addr: Address that must be contained within the new function

    :returns: Function object if successful.
    """
    # First check if function already exists.
    if func := dis.get_function(addr, None):
        return func
    if cant_create_function(dis, addr):
        return None

    # Attempt to find possible function starts at lower addresses than the provided address
    # so the function will contain the provided address.
    for start in find_start_bounds(dis, addr):
        if func := dis.create_function(start, default=None):
            if addr in func:
                return func
            func.undefine()
