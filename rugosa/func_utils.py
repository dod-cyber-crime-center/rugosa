"""
Helper utilities for functions.
"""
import collections
import warnings

import dragodis
from dragodis.interface import Function

__all__ = [
    "from_name",
    "api_calls",
]


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
