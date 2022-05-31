from rugosa.emulation.constants import DWORD
from rugosa.emulation.emulator import Emulator
from rugosa.emulation.flowchart import iter_paths


def test_flowchart(disassembler):
    # NOTE: Need to turn off teleportation here due to direct interaction with the path nodes.
    emulator = Emulator(disassembler, teleport=False)

    # Test on simple 1 block function.
    flowchart = disassembler.get_flowchart(0x004011AA)

    # Ensure we create a path of just the 1 block.
    paths = list(iter_paths(flowchart, 0x004011AA))
    assert len(paths) == 1
    path = paths[0]
    assert list(path) == [path.block]
    assert 0x004011AA in path
    assert 0xFF not in path
    assert path.block in path
    # Ensure cpu context gets created correctly.
    cpu_context = path.cpu_context(init_context=emulator.new_context())
    assert cpu_context.ip == path.block.end
    cpu_context = path.cpu_context(0x0040115D, init_context=emulator.new_context())
    assert cpu_context.ip == 0x0040115D

    # TODO: This whole thing doesn't make sense.
    memory = cpu_context.memory
    # Test read_data()
    data_ptr = memory.read_data(cpu_context.registers.esp, data_type=DWORD)
    assert memory.read_data(data_ptr) == b"Idmmn!Vnsme "
    # Test write_data()
    memory.write_data(cpu_context.registers.esp, data_ptr + 3, data_type=DWORD)
    data_ptr = memory.read_data(cpu_context.registers.esp, data_type=DWORD)
    assert memory.read_data(data_ptr) == b"mn!Vnsme "

    # Test on slightly more complex function with 5 blocks
    flowchart = disassembler.get_flowchart(0x004035BB)

    paths = list(iter_paths(flowchart, 0x004035B1))
    assert len(paths) == 1
    assert [block.start for block in paths[0]] == [0x00403597, 0x004035AB, 0x004035B1]

    paths = list(iter_paths(flowchart, 0x004035BC))
    assert len(paths) == 3
    assert sorted([block.start for block in path] for path in paths) == [
        [0x00403597, 0x004035AB, 0x004035B1, 0x004035B3, 0x004035BA],
        [0x00403597, 0x004035AB, 0x004035B3, 0x004035BA],
        [0x00403597, 0x004035BA],
    ]


def test_context_depth(disassembler):
    """Tests depth feature in iter_context_at()"""
    emulator = Emulator(disassembler)

    # TODO: This is not a great test because we only have 1 path at each level.
    #   Create a new sample with more complex calculations.
    ea = 0x401029  # Address in function that contains multiple paths.
    num_paths_first_depth = 1
    num_paths_second_depth = 1
    num_calls = 18

    # First ensure paths are calculated correctly.
    flowchart = disassembler.get_flowchart(ea)
    assert len(list(iter_paths(flowchart, ea))) == num_paths_first_depth

    func = disassembler.get_function(ea)
    call_eas = list(func.calls_to)
    assert len(call_eas) == num_calls
    call_ea = call_eas[0]
    assert call_ea == 0x40103A
    flowchart = disassembler.get_flowchart(call_ea)
    block = flowchart.get_block(call_ea)
    assert len(list(iter_paths(flowchart, block.start))) == num_paths_second_depth

    # Now show that we get the correct number of contexts based on depth and other parameters.

    # Test getting contexts for only the first depth.
    ctxs = list(emulator.iter_context_at(ea))
    assert len(ctxs) == num_paths_first_depth
    # (exhaustive has no affect on final call level)
    ctxs = list(emulator.iter_context_at(ea, exhaustive=False))
    assert len(ctxs) == num_paths_first_depth

    # Test getting contexts with 2 depths.
    ctxs = list(emulator.iter_context_at(ea, depth=1))
    assert len(ctxs) == num_paths_first_depth * num_paths_second_depth * num_calls
    ctxs = list(emulator.iter_context_at(ea, depth=1, exhaustive=False))
    assert len(ctxs) == num_paths_first_depth * num_calls

