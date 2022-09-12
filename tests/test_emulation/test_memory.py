import os

import pytest
from textwrap import dedent

from rugosa.emulation.emulator import Emulator


def test_memory(disassembler):
    """Tests the memory controller."""
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    memory = context.memory

    # basic test
    assert memory.read(0x00121000, 10) == b"\x00" * 10

    # test reading across pages
    memory.write(0x00121FFB, b"helloworld")
    assert memory.read(0x00121FFB, 10) == b"helloworld"
    assert memory.read(0x00121FFB + 10, 10) == b"\x00" * 10
    assert memory.read(0x00121FFB + 5, 10) == b"world" + b"\x00" * 5

    # test reading segment data
    assert memory.read(0x0040C000, 11) == b"Idmmn!Vnsme"
    assert memory.read(0x00401150, 3) == b"\x55\x8B\xEC"

    # test str print
    # (not testing the full printout because segments and their sizes can differ for each disassembler)
    min_addr = disassembler.min_address
    print(str(memory))
    assert str(memory).startswith(dedent(f"""\
        Base Address             Address Range            Size
        0x00121000               0x00121000 - 0x00123000  8192
        0x{min_addr:08X}               0x{min_addr:08X} - """))

    # test searching
    assert memory.find(b"helloworld", start=0x0011050) == 0x00121FFB
    assert memory.find(b"helloworld") == 0x00121FFB
    assert memory.find(b"helloworld", start=0x00121FFC) == -1
    assert memory.find(b"helloworld", end=0x10) == -1
    assert memory.find(b"helloworld", start=0x0011050, end=0x00121FFB) == -1
    assert memory.find(b"helloworld", start=0x0011050, end=0x00122000) == -1
    assert memory.find(b"helloworld", start=0x0011050, end=0x00122100) == 0x00121FFB
    assert memory.find(b"`QFBWF") == 0x0040C120
    assert memory.find(b"Idmmn!Vnsme") == 0x0040C000
    assert memory.find_in_segment(b"Idmmn!Vnsme", ".data") == 0x0040C000
    assert memory.find_in_segment(b"Idmmn!Vnsme", ".text") == -1
    assert memory.find(b"\x5F\x5E\xC3", start=0x004035BD) == 0x004035E0

    # test bugfix when searching single length characters
    assert memory.find(b"h", start=0x0011050) == 0x00121FFB
    assert memory.find(b"h", start=0x0011050, end=0x00121FFB) == -1
    assert memory.find(b"h", start=0x0011050, end=0x00121FFB + 1) == 0x00121FFB
    assert memory.find(b"o", start=0x0011050) == 0x00121FFB + 4

    # tests allocations
    first_alloc_ea = memory.alloc(10)
    assert first_alloc_ea == memory._heap_base
    second_alloc_ea = memory.alloc(20)
    assert second_alloc_ea == memory._heap_base + 10 + memory.HEAP_SLACK
    memory.write(second_alloc_ea, b"im in the heap!")
    assert memory.read(second_alloc_ea, 15) == b"im in the heap!"
    assert memory.find_in_heap(b"the heap!") == second_alloc_ea + 6
    memory.write(second_alloc_ea, b"helloworld")
    assert memory.find_in_heap(b"helloworld") == second_alloc_ea

    # tests reallocations
    assert memory.realloc(first_alloc_ea, 40) == first_alloc_ea  # no relocation
    assert memory.realloc(first_alloc_ea, memory.PAGE_SIZE * 5) == second_alloc_ea + 20 + memory.HEAP_SLACK  # relocation
    assert memory.realloc(second_alloc_ea, 40) == second_alloc_ea  # no relocation
    second_alloc_realloced_ea = memory.realloc(second_alloc_ea, memory.PAGE_SIZE * 6)
    assert second_alloc_realloced_ea != second_alloc_ea
    assert memory.read(second_alloc_realloced_ea, 10) == b"helloworld"  # data should be copied over.


@pytest.mark.parametrize("address,data", [
    (0x10544, b"\x28\x10\x02\x00"),
    (0x21028, b"Idmmn!Vnsme \x00"),
])
def test_memory_arm(disassembler, address, data):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    memory = context.memory

    assert disassembler.get_bytes(address, len(data)) == data
    assert memory.read(address, len(data)) == data


def test_cache_clear(disassembler):
    """
    Tests clearing cache will cause emulator to re-retrieve data from the underlying disassembler.
    (Necessary when patching data with the disassembler.)
    """
    address = 0x40C000
    data = b"Idmmn!Vnsme"
    new_data = b"hello world"

    emulator = Emulator(disassembler)
    context = emulator.new_context()
    memory = context.memory

    # confirm we can get the original data.
    assert memory.read(address, len(data)) == data
    # patch the memory with something new.
    with disassembler.get_segment(".data").open() as memory_stream:
        memory_stream.seek_address(address)
        memory_stream.write(new_data)
    # we still shouldn't have been able to get the new patched bytes yet due to caching
    assert memory.read(address, len(data)) == data
    assert emulator.new_context().memory.read(address, len(data)) == data
    # clear cache and see if we now get the new data.
    emulator.clear_cache()
    assert memory.read(address, len(data)) == new_data
    assert emulator.new_context().memory.read(address, len(data)) == new_data

    # reset
    with disassembler.get_segment(".data").open() as memory_stream:
        memory_stream.seek_address(address)
        memory_stream.reset(len(data))
    emulator.clear_cache()
    assert memory.read(address, len(data)) == data
    assert emulator.new_context().memory.read(address, len(data)) == data


def test_streaming(disassembler):
    """
    Tests creating a file-like stream for emulated memory.
    """
    emulator = Emulator(disassembler)
    context = emulator.new_context()

    with context.memory.open() as stream:
        assert stream.tell() == 0
        assert stream.tell_address() in (0x400000, 0x401000)

        stream.seek_address(0x40C000)
        assert stream.read(11) == b"Idmmn!Vnsme"
        assert stream.tell_address() == 0x40C000 + 11

        data = stream.read()
        # Size depends on disassembler and whether they include the trailing uninitialized bytes.
        assert len(data) in (8181, 12277)
        assert data.startswith(b' \x00\x00\x00\x00Vgqv"qvpkle"ukvj"ig{')

    with context.memory.open(0x40C000) as stream:
        assert stream.read(11) == b"Idmmn!Vnsme"
        assert stream.write(b"hello") == 5
        assert stream.tell() == 16
        assert stream.seek(-5, os.SEEK_CUR) == 11
        assert context.memory.read(0x40C000 + 11, 5) == b"hello"
        assert stream.read(5) == b"hello"
