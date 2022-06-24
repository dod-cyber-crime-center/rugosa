"""
Extra utility functions for interfacing within a dragodis disassembly
"""

from typing import Union, List, Iterable, Tuple, Optional

import logging

import dragodis
from dragodis import Disassembler, ReferenceType, NotExistError, OperandType
from dragodis.interface import Function

logger = logging.getLogger(__name__)


def iter_imports(dis: Disassembler, module_name=None, api_names=None) -> Iterable[Tuple[int, str, str]]:
    """
    Iterate the thunk function wrappers for API imports.
    Yields the module name, function name, and reference to function.

    .. code_block:: python

        for ea, name, module_name in utils.iter_imports():
            print("{}.{} function at: 0x{:0x}".format(module_name, name, ea))

        for ea, name, _ in utils.iter_imports("KERNEL32"):
            print("KERNEL32.{} function at: {}".format(name, ea))

        for ea, name, module_name in utils.iter_imports(api_names=["GetProcAddress", "GetFileSize"]):
            print("{}.{} function at: {}".format(module_name, name, ea))

        for ea, _, _ in utils.iter_imports("KERNEL32", "GetProcAddress"):
            print("KERNEL32.GetProcAddress function at: {}".format(ea))

    NOTE: The same function name can be yield more than once if it
    appears in multiple modules or has multiple thunk wrappers.

    Name is the original import name and does not necessarily reflect the function name.
    e.g. "GetProcAddress", "GetProcAddress_0", and "GetProcAddress_1" will all be "GetProcAddress"

    :param dis: Dragodis disassembler
    :param module_name: Filter imports to a specified library.
    :param api_names: Filter imports to specific API name(s).
        Can be a string of a single name or list of names.

    :yield: (ea, api_name, module_name)
    """
    if isinstance(api_names, str):
        api_names = [api_names]

    for import_ in dis.imports:
        # Some disassemblers include the ".dll" while others do not.
        namespace = import_.namespace.lower().rstrip(".dll")
        if module_name and namespace != module_name.lower():
            continue
        if _match_name(api_names, import_.name):
            yield import_.address, import_.name, namespace


# TODO: This function needs to be reworked.
def iter_dynamic_functions(dis: Disassembler) -> Iterable[Tuple[int, str]]:
    """
    Iterates the dynamically resolved function signatures.

    :yield: (ea, name)
    """
    try:
        data_segment = dis.get_segment(".data")
    except NotExistError:
        return
    for line in data_segment.lines:
        try:
            value = line.value
        except NotImplementedError:
            # TODO: For now, ignore dynamic functions within structs.
            continue
        if isinstance(value, int):
            try:
                dis.get_function(value)
                yield line.address, line.name
            except NotExistError:
                continue


def _match_name(func_names: Optional[List[str]], name: Optional[str]) -> bool:
    if not func_names:
        return True
    if not name:
        return False
    return (
        name in func_names
        or any(func_name in name for func_name in func_names)
    )


def iter_functions(dis: Disassembler, func_names: Union[None, str, List[str]] = None) -> Iterable[Tuple[int, str]]:
    """
    Iterate all defined functions and yield their address and name.
    (This includes imported and dynamically generated functions)

    :param func_names: Filter based on specific function names.

    :yield: (ea, name)
    """
    if isinstance(func_names, str):
        func_names = [func_names]

    # Yield declared functions.
    for func in dis.functions():
        name = func.name
        if _match_name(func_names, name):
            yield func.start, name

    # Also yield from imported.
    for import_ in dis.imports:
        if _match_name(func_names, import_.name):
            yield import_.address, import_.name

    # Yield dynamically resolved functions.
    for ea, name in iter_dynamic_functions(dis):
        if _match_name(func_names, name):
            yield ea, name


def iter_calls_to(dis: Disassembler, addr: int) -> Iterable[int]:
    """
    Iterates the calls to the given address.

    :param dis: dragodis Disassembler object
    :param func_ea: Address of a function call.
    :yields: Call instruction address
    """
    line = dis.get_line(addr)
    for ref in line.references_to:
        if ref.type == ReferenceType.code_call:
            yield ref.from_address


def iter_import_calls(dis: Disassembler, name: str) -> Iterable[int]:
    """
    Iterates the calls to a given import by name.

    :param dis: dragodis Disassembler object
    :param name:  name of import function
    :yields: Call instruction address
    """
    imp = dis.get_import(name)
    for ref in imp.references_to:
        if ref.type == ReferenceType.code_call:
            yield ref.from_address


def iter_import_callers(dis: Disassembler, name: str) -> Iterable[Function]:
    """
    Iterates Function objects that call the given import.

    :param dis: dragodis Disassembler object
    :param name: name of import function
    :yields: Call instruction address
    """
    cache = set()
    for call_addr in iter_import_calls(dis, name):
        try:
            func = dis.get_function(call_addr)
        except NotExistError:
            continue
        if func.name not in cache:
            yield func
            cache.add(func.name)


def iter_callers(dis: Disassembler, addr: int) -> Iterable[Function]:
    """
    Iterates Function objects that call the given address.

    :param addr: Address of a function call.
    :return:
    """
    cache = set()
    for call_addr in iter_calls_to(dis, addr):
        try:
            func = dis.get_function(call_addr)
        except NotExistError:
            continue
        if func.name not in cache:
            yield func
            cache.add(func.name)


def get_import_addr(dis: Disassembler, api_name, module_name=None) -> Optional[int]:
    """
    Returns the first instance of a function that wraps the given API name.

    .. code_block:: python

        proc_func_ea = get_import_addr("GetProcAddress")

    :param dis: Dragodis disassembler
    :param api_name: Name of API
    :param module_name: Library of API

    :returns: Address of function start or None if not found.
    """
    for ea, _, _ in iter_imports(dis, module_name, api_name):
        return ea


def get_export_addr(dis: Disassembler, export_name) -> Optional[int]:
    """
    Return the location of an export by name

    :param dis: Dragodis disassembler
    :param export_name: Target export

    :return: Location of target export or None
    """
    for export in dis.exports:
        if export.name == export_name:
            return export.address


def get_function_addr(dis: Disassembler, func_name: str) -> Optional[int]:
    """
    Obtain a function in the list of functions for the application by name.
    Supports using API resolved names if necessary.

    :param dis: Dragodis disassembler
    :param func_name: Name of function to obtain

    :return: start_ea of function or None
    """
    for ea, _ in iter_functions(dis, func_name):
        return ea


RAX_FAM = ["rax", "eax", "ax", "ah", "al"]


def find_destination(dis: Disassembler, start, instruction_limit=None) -> Optional[int]:
    """
    Finds the destination address for returned eax register.

    :param dis: Dragodis disassembler
    :param int start: Starting address to start looking
    :param int instruction_limit: Limit the number of instructions to traverse before giving up.
        Defaults to searching until the end of the function.

    :return: destination address or None if address couldn't be found or is not a loaded address.
    """
    count = 0
    func = dis.get_function(start)
    for insn in func.instructions(start):
        count += 1
        if instruction_limit is not None and count > instruction_limit:
            return None

        if insn.mnemonic == "mov" and insn.operands[1].text.lower() in RAX_FAM:
            if insn.operands[0].type == OperandType.memory:
                return insn.operands[0].value
            else:
                return None
    return None
