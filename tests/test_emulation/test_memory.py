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
    min_addr = disassembler.min_address
    assert str(memory) == dedent(
        f"""\
        Base Address             Address Range            Size
        0x00121000               0x00121000 - 0x00123000  8192
        0x{min_addr:08X}               0x{min_addr:08X} - 0x0040E000  {0x40E000-min_addr}
    """
    )

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
