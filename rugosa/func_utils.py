"""
Helper utilities for functions.
"""
import collections

import dragodis
from dragodis.interface import Function

__all__ = [
    "from_name",
    "api_calls",
]


def from_name(dis: dragodis.Disassembler, func_name: str, ignore_underscore: bool = False) -> Function:
    """
    Factory method for obtaining a Function by name.

    e.g.
        with dragodis.open_program("input.exe") as dis:
            func = functions.from_name(dis, "WriteFile")

    :param dis: Dragodis disassembler
    :param str func_name: Name of function to obtain
    :param bool ignore_underscore: Whether to ignore underscores in function name.
        (Will return the first found function if enabled.)

    :return: Function object
    :raises ValueError: If function name was not found.
    """
    for func in dis.functions():
        _func_name = func.name
        if ignore_underscore:
            _func_name = _func_name.strip("_")
        if func_name == _func_name:
            return func
    raise ValueError(f"Unable to find function with name: {func_name}")


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
