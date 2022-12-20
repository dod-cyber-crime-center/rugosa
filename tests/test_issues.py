"""
Tests for bug fixes reported on GitHub.
"""

import pytest

import dragodis
from rugosa.emulation.emulator import Emulator
from rugosa.emulation.constants import WIDE_STRING


def test_issue_7(disassembler):
    """Tests the use of WIDE_STRING for read_data()"""
    emulator = Emulator(disassembler)
    context = emulator.new_context()

    wide_string = b"/\x00f\x00a\x00v\x00.\x00i\x00c\x00o\x00"
    context.memory.write(0x123000, wide_string)
    assert context.memory.read_data(0x123000, data_type=WIDE_STRING) == wide_string
    wide_string = b"\x00/\x00f\x00a\x00v\x00.\x00i\x00c\x00o"
    context.memory.write(0x123000, wide_string)
    assert context.memory.read_data(0x123000, data_type=WIDE_STRING) == wide_string


# TODO: Need to test this in both x86 and ARM
#   - Bring over or import the naming thing for disassembler.
def test_function_case_senstivity_all(disassembler):
    """Tests issue with case sensitivity when hooking functions."""
    emulator = Emulator(disassembler)

    # NOTE: Can't check equality of the functions directly since emulator could be teleported.

    # Test with known builtin func
    assert emulator.get_call_hook("lstrcpya").__name__ == "strcpy"
    assert emulator.get_call_hook("lStrcpyA").__name__ == "strcpy"
    assert emulator.get_call_hook("lstrcpyA").__name__ == "strcpy"

    # Test user defined
    def dummy(ctx, func_name, func_args):
        return

    assert emulator.get_call_hook("SuperFunc") is None
    assert emulator.get_call_hook("SUPERfunc") is None
    assert emulator.get_call_hook("superfunc") is None
    emulator.hook_call("SuperFunc", dummy)
    assert emulator.get_call_hook("SuperFunc").__name__ == "dummy"
    assert emulator.get_call_hook("SUPERfunc").__name__ == "dummy"
    assert emulator.get_call_hook("superfunc").__name__ == "dummy"


def test_multiple_emulations(strings_x86):
    """
    Tests issue with stale caching when multiple emulations happen in same process but different dragodis disassemblies.
    """
    address = 0x401024

    try:
        with dragodis.open_program(strings_x86, "ida") as dis:
            emulator = Emulator(dis, teleport=False)
            ctx = emulator.context_at(address)

        with dragodis.open_program(strings_x86, "ida") as dis:
            emulator = Emulator(dis, teleport=False)
            ctx = emulator.context_at(address)
    except dragodis.NotInstalledError as e:
        pytest.skip(str(e))

    # We pass if we don't get an EOFError raised.
