
import pytest

from rugosa.emulation.emulator import Emulator
from rugosa.emulation.exceptions import EmulationError


def test_barrel_shifted_operands_arm(disassembler):
    """Tests ARM's barrel shifted operand types"""
    emulator = Emulator(disassembler)

    # MOV     R1, R3,LSR#31
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x103A4)
    ctx.ip = insn.ip
    assert insn.operands[1].text in ("R3,LSR#31", "r3, lsr #0x1f")
    ctx.registers.r3 = 0xffffffff
    ctx.registers.c = 0
    assert ctx.registers.r3 == 0xffffffff
    assert ctx.registers.c == 0
    assert insn.operands[1].value == 0x1
    assert ctx.registers.c == 0  # carry flag should have not been updated, (not MOVS)

    # ADD     R1, R1, R3,ASR#2
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x103A8)
    ctx.ip = insn.ip
    assert insn.operands[2].text in ("R3,ASR#2", "r3, asr #0x2")
    ctx.registers.r3 = 0x1013
    ctx.registers.c = 0
    assert insn.operands[2].value == 0x1013 >> 2
    assert ctx.registers.c == 0  # carry flag should have not been updated, (not ADDS)
    # Test again with a negative number to ensure ASR sign extends appropriately.
    ctx.registers.r3 = -0x1013
    assert ctx.registers.r3 == 0xffffefed   # sanity check
    assert insn.operands[2].value == 0xfffffbfb  # sign extended shift right 2
    assert ctx.registers.c == 0

    # MOVS    R1, R1,ASR#1
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x103AC)
    ctx.ip = insn.ip
    assert insn.operands[1].text in ("R1,ASR#1", "r1, asr #0x1")
    ctx.registers.r1 = 0x1013
    ctx.registers.c = 0
    assert insn.operands[1].value == 0x1013 >> 1
    assert ctx.registers.c == 1  # carry flag should be affected (MOVS)
    # reset instruction pointer to ensure carry flag is only affected if ip is the same.
    ctx.ip = 0
    assert ctx.ip != insn.ip
    ctx.registers.r1 = 0x1013
    ctx.registers.c = 0
    assert insn.operands[1].value == 0x1013 >> 1
    assert ctx.registers.c == 0  # carry flag should not be affected, (ctx.ip != insn.ip)

    # Ensure proper error is thrown if we attempt to set the operand value.
    with pytest.raises(EmulationError):
        insn.operands[1].value = 10


def test_register_list_operands_arm_ida(disassembler):
    """Tests ARM operands that are register lists."""
    emulator = Emulator(disassembler)

    # POPEQ   {R4-R10,PC}
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x106A8)
    assert insn.operands[0].text == "{R4-R10,PC}"
    # Casting is necessary if emulator is teleported.
    assert list(insn.operands[0].register_list) == ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "pc"]
    ctx.registers.r4 = 4
    ctx.registers.r5 = 5
    ctx.registers.r6 = 6
    ctx.registers.r7 = 7
    ctx.registers.r8 = 8
    ctx.registers.r9 = 9
    ctx.registers.r10 = 10
    ctx.registers.pc = 1024
    assert list(insn.operands[0].value) == [4, 5, 6, 7, 8, 9, 10, 1024]
    insn.operands[0].value = [10, 20, 30, 40, 50, 60, 70, 80]
    assert list(insn.operands[0].value) == [10, 20, 30, 40, 50, 60, 70, 80]
    assert ctx.registers.r4 == 10
    assert ctx.registers.r5 == 20
    assert ctx.registers.r6 == 30
    assert ctx.registers.r7 == 40
    assert ctx.registers.r8 == 50
    assert ctx.registers.r9 == 60
    assert ctx.registers.r10 == 70
    assert ctx.registers.pc == 80

    # ValueError should be thrown if we set the wrong amount of values.
    with pytest.raises(ValueError):
        insn.operands[0].value = [1, 2, 3]


def test_register_list_operands_arm_ghidra(disassembler):
    """Tests ARM operands that are register lists."""
    emulator = Emulator(disassembler)

    # ldmiaeq    sp!,{r4 r5 r6 r7 r8 r9 r10 pc}
    ctx = emulator.new_context()
    insn = ctx.get_instruction(0x106A8)
    # WARNING: Ghidra merges the operands into 1 for some reason.
    assert insn.operands[0].text == "sp!,{r4 r5 r6 r7 r8 r9 r10 pc}"
    assert insn.operands[0].register_list == ["sp", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "pc"]
    ctx.registers.sp = 3
    ctx.registers.r4 = 4
    ctx.registers.r5 = 5
    ctx.registers.r6 = 6
    ctx.registers.r7 = 7
    ctx.registers.r8 = 8
    ctx.registers.r9 = 9
    ctx.registers.r10 = 10
    ctx.registers.pc = 1024
    assert insn.operands[0].value == [3, 4, 5, 6, 7, 8, 9, 10, 1024]
    insn.operands[0].value = [5, 10, 20, 30, 40, 50, 60, 70, 80]
    assert insn.operands[0].value == [5, 10, 20, 30, 40, 50, 60, 70, 80]
    assert ctx.registers.sp == 5
    assert ctx.registers.r4 == 10
    assert ctx.registers.r5 == 20
    assert ctx.registers.r6 == 30
    assert ctx.registers.r7 == 40
    assert ctx.registers.r8 == 50
    assert ctx.registers.r9 == 60
    assert ctx.registers.r10 == 70
    assert ctx.registers.pc == 80

    # ValueError should be thrown if we set the wrong amount of values.
    with pytest.raises(ValueError):
        insn.operands[0].value = [1, 2, 3]


def test_memory_addressing_modes_arm(disassembler):
    """Tests pre/post indexed memory address operands."""
    emulator = Emulator(disassembler)

    # Post-index
    # LDR     R3, [R5],#4
    ctx = emulator.new_context()
    ctx.memory.write(0, bytes(range(100)))
    insn = ctx.get_instruction(0x106BC)
    assert insn.operands[1].text in ("[R5],#4", "[r5],#0x4")
    ctx.registers.r5 = 5
    # operand initially points to address 0x5
    assert insn.operands[1].addr == 5
    assert insn.operands[1].value == 0x8070605
    insn.execute()
    # operand should now point to address 0x5 + 4
    assert ctx.registers.r5 == 5 + 4
    assert insn.operands[1].addr == 5 + 4
    assert insn.operands[1].value == 0xc0b0a09

    # Pre-index (no update)
    # LDR     R2, [R3,R2]
    ctx = emulator.new_context()
    ctx.memory.write(0, bytes(range(100)))
    insn = ctx.get_instruction(0x10354)
    assert insn.operands[1].text in ("[R3,R2]", "[r3,r2]")
    ctx.registers.r2 = 2
    ctx.registers.r3 = 3
    # operand initially points to address 3 + 2
    assert insn.operands[1].addr == 3 + 2
    assert insn.operands[1].value == 0x8070605
    insn.execute()
    # operands should still point to address 3 + 2
    assert ctx.registers.r3 == 3
    ctx.registers.r2 = 2  # undo the modification to R2 the instruction does :)
    assert insn.operands[1].addr == 3 + 2
    assert insn.operands[1].value == 0x8070605

    # Pre-index with update
    # LDR     PC, [LR,#8]!
    ctx = emulator.new_context()
    ctx.memory.write(0, bytes(range(100)))
    insn = ctx.get_instruction(0x102D4)
    assert insn.operands[1].text in ("[LR,#8]!", "[LR,#(off_21008 - 0x21000)]!", "[lr,#0x8]!")
    ctx.registers.lr = 2
    # operand initially points to address 0x2 + 8
    assert insn.operands[1].addr == 2 + 8
    assert insn.operands[1].value == 0xd0c0b0a
    insn.execute()
    # operand should now point to address 0x2 + 8 + 8
    assert ctx.registers.lr == 2 + 8
    assert insn.operands[1].addr == 2 + 8 + 8
    assert insn.operands[1].value == 0x15141312

