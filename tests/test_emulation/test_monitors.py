from rugosa import ProcessorContext, Emulator
from rugosa.emulation import Monitor
from rugosa.emulation.instruction import Instruction


def test_post_instruction(disassembler):
    seen = []
    class MyMonitor(Monitor):
        def post_instruction(self, context: ProcessorContext, instruction: Instruction):
            seen.append(instruction.ip)

    emu = Emulator(disassembler)
    emu.add_monitor(MyMonitor())
    emu.context_at(0x004011CE)

    assert seen == [
        0x401150, 0x401151, 0x401153, 0x401158, 0x40115d, 0x401162, 0x401167, 0x40116a, 0x40116f, 0x401174,
        0x401179, 0x40117c, 0x401181, 0x401186, 0x40118b, 0x40118e, 0x401193, 0x401198, 0x40119d, 0x4011a0,
        0x4011a5, 0x4011aa, 0x4011af, 0x4011b2, 0x4011b7, 0x4011bc, 0x4011c1, 0x4011c4, 0x4011c9
    ]


def test_callbacks(disassembler):
    seen = []
    emu = Emulator(disassembler)
    emu.add_monitor(post_instruction=lambda _, insn: seen.append(insn.ip))
    emu.context_at(0x004011CE)

    assert seen == [
        0x401150, 0x401151, 0x401153, 0x401158, 0x40115d, 0x401162, 0x401167, 0x40116a, 0x40116f, 0x401174,
        0x401179, 0x40117c, 0x401181, 0x401186, 0x40118b, 0x40118e, 0x401193, 0x401198, 0x40119d, 0x4011a0,
        0x4011a5, 0x4011aa, 0x4011af, 0x4011b2, 0x4011b7, 0x4011bc, 0x4011c1, 0x4011c4, 0x4011c9
    ]


def test_block_end(disassembler):
    seen = []
    emu = Emulator(disassembler)
    emu.add_monitor(block_end=lambda _, insn: seen.append(insn.ip))
    emu.context_at(0x40102a)
    assert seen == [0x401001, 0x40100b]


def test_exhaust(disassembler):
    """
    Test with a monitor that just records everything.
    """
    class RecordAll(Monitor):
        def __init__(self):
            self.instructions = []
            self.block_starts = []
            self.block_ends = []
            self.function_starts = []
            self.function_ends = []
            self.code_path_ends = []

        def post_instruction(self, context: ProcessorContext, instruction: Instruction):
            self.instructions.append(instruction.ip)
        def block_start(self, context: ProcessorContext, instruction: Instruction):
            self.block_starts.append(instruction.ip)
        def block_end(self, context: ProcessorContext, instruction: Instruction):
            self.block_ends.append(instruction.ip)
        def function_start(self, context: ProcessorContext, instruction: Instruction):
            self.function_starts.append(instruction.ip)
        def function_end(self, context: ProcessorContext, instruction: Instruction):
            self.function_ends.append(instruction.ip)
        def code_path_end(self, context: ProcessorContext, instruction: Instruction):
            self.code_path_ends.append(instruction.ip)

    records = RecordAll()
    emu = Emulator(disassembler)
    with emu.monitor(records):
        emu.exhaust(0x401000)

    assert records.instructions == [
        0x401000, 0x401001,
        0x401003, 0x401006, 0x401009, 0x40100b,
        0x40100d, 0x401011, 0x401014, 0x401017, 0x401019, 0x40101c, 0x40101e, 0x401021, 0x401024, 0x401027,
        0x401029, 0x40102a
    ]
    assert records.block_starts == [0x401000, 0x401003, 0x40100d, 0x401029]
    assert records.block_ends == [0x401001, 0x40100b, 0x401027, 0x40102a]
    assert records.function_starts == [0x401000]
    assert records.function_ends == [0x40102a]
    assert records.code_path_ends == [0x401027, 0x40102a]
