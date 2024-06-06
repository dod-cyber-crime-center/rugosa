"""
ARM opcodes
"""

import logging
import typing

from .. import utils
from ..cpu_context import ProcessorContext
from ..instruction import Instruction
from ..exceptions import EmulationError
from ..opcode import opcode_registrar
from . import utils as arm_utils


logger = logging.getLogger(__name__)


# Dictionary containing opcode names -> function
OPCODES = {}

if typing.TYPE_CHECKING:
    from ..opcode import opcode
else:
    # only assign this at runtime, so we can keep the stub docs and typing
    opcode = opcode_registrar(OPCODES)


@opcode
def NOP(cpu_context: ProcessorContext, instruction: Instruction):
    return


#region Conditional branch instructions


@opcode
def CBNZ(cpu_context: ProcessorContext, instruction: Instruction):
    """Compare and branch if nonzero"""
    operands = instruction.operands
    value = operands[0].value
    jump_target = operands[1].value

    if value != 0:
        cpu_context.ip = jump_target

    # TODO: Update branch tracking.


@opcode
def CBZ(cpu_context: ProcessorContext, instruction: Instruction):
    """Compare and branch if zero"""
    operands = instruction.operands
    value = operands[0].value
    jump_target = operands[1].value

    if value == 0:
        cpu_context.ip = jump_target

    # TODO: Update branch tracking.


@opcode
def TBNZ(cpu_context: ProcessorContext, instruction: Instruction):
    """Test bit and branch if nonzero"""
    operands = instruction.operands
    value = operands[0].value
    bit_number = operands[1].value
    jump_target = operands[2].value

    if value & (1 << bit_number) != 0:
        cpu_context.ip = jump_target

    # TODO: Update branch tracking.


@opcode
def TBZ(cpu_context: ProcessorContext, instruction: Instruction):
    """Test bit and branch if zero"""
    operands = instruction.operands
    value = operands[0].value
    bit_number = operands[1].value
    jump_target = operands[2].value

    if value & (1 << bit_number) == 0:
        cpu_context.ip = jump_target

    # TODO: Update branch tracking.

#endregion

#region Unconditional branch (immediate/register)

@opcode("b")
@opcode("br")
@opcode("bx")
def B(cpu_context: ProcessorContext, instruction: Instruction):
    """Branch unconditionally"""
    cpu_context.ip = instruction.operands[0].value


@opcode("bl")
@opcode("blr")
@opcode("blx")
def BL(cpu_context: ProcessorContext, instruction: Instruction):
    """Branch with link"""
    operands = instruction.operands
    # Function pointer can be a memory reference or immediate.
    func_ea = operands[0].addr or operands[0].value
    # Using signature to get demangled name.
    func_name = cpu_context.emulator.disassembler.get_function_signature(func_ea).name

    logger.debug("call %s", func_name or f"0x{func_ea:X}")

    # Store next ip to lr register.
    cpu_context.registers.lr = instruction.ip + 4
    # Branch
    cpu_context.ip = operands[0].value

    if operands[0].is_func_ptr:
        cpu_context._execute_call(func_ea, func_name, instruction.ip)

    # Restore instruction pointer to return address.
    cpu_context.ip = cpu_context.registers.lr

#endregion

#region System register instructions


@opcode("mrs")
@opcode("msr")
def _mov(cpu_context: ProcessorContext, instruction: Instruction):
    operands = instruction.operands
    operands[0].value = operands[1].value

#endregion

#region Load/Store register

@opcode
def LDR(cpu_context: ProcessorContext, instruction: Instruction):
    """Load with immediate"""
    operands = instruction.operands
    operands[0].value = operands[1].value


@opcode
def STR(cpu_context: ProcessorContext, instruction: Instruction):
    """Store with immediate"""
    operands = instruction.operands
    operands[1].value = operands[0].value

#endregion

#region Load/Store register (unscaled offset)

# TODO: Can LDUR just be an alias for LDR?
@opcode
def LDUR(cpu_context: ProcessorContext, instruction: Instruction):
    """Load register (unscaled offset)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


# TODO: Can STUR just be an alias for STR?
@opcode
def STUR(cpu_context: ProcessorContext, instruction: Instruction):
    """Store register (unscaled offset)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Load Multiple (Increment After, Full Descending)


def _pop(cpu_context, reg_list):
    for reg_name in reg_list:
        data = cpu_context.memory.read(cpu_context.sp, 4)
        value = int.from_bytes(data, cpu_context.byteorder)
        cpu_context.registers[reg_name] = value
        cpu_context.sp += 4


@opcode
def LDM(cpu_context: ProcessorContext, instruction: Instruction):
    """Load Multiple Registers"""
    operands = instruction.operands

    # If we only have one operand, this is Ghidra's version of a POP.
    if len(operands) == 1 and operands[0].text.startswith("sp!"):
        _pop(cpu_context, operands[0].register_list[1:])
        return

    reg_list = operands[1].register_list
    if not reg_list:
        raise EmulationError(f"Expected {operands[1].text} to be a register list.")

    for reg_name in reg_list:
        data = cpu_context.memory.read(operands[0].value, 4)
        value = int.from_bytes(data, cpu_context.byteorder)
        cpu_context.registers[reg_name] = value
        # TODO: confirm operand is auto-increased in ARMInstruction._execute()


@opcode
def POP(cpu_context: ProcessorContext, instruction: Instruction):
    """Load Multiple Register from Stack"""
    operands = instruction.operands
    reg_list = operands[0].register_list
    if not reg_list:
        raise EmulationError(f"Expected {operands[0].text} to be a register list.")

    _pop(cpu_context, reg_list)


#endregion

#region Store Multiple (Increment After, Empty Ascending)


def _push(cpu_context, reg_values):
    # .value is a list of register values from lowest to highest.
    # Registers are pushed from largest to smallest for PUSH.
    for value in reversed(reg_values):
        cpu_context.sp -= 4
        cpu_context.memory.write_data(cpu_context.sp, value)


@opcode
def STM(cpu_context: ProcessorContext, instruction: Instruction):
    """Store Multiple Registers"""
    operands = instruction.operands

    # If we only have one operand, this is Ghidra's version of a PUSH.
    if len(operands) == 1 and operands[0].text.startswith("sp!"):
        _push(cpu_context, operands[0].value[1:])
        return

    reg_values = operands[1].value  # .value is a list of values
    if not isinstance(reg_values, list):
        raise EmulationError(f"Expected {operands[1].text} to be a register list.")

    for value in reversed(reg_values):
        cpu_context.memory.write_data(operands[0].value, value)
        # TODO: confirm operand is auto-decreased in ARMInstruction._execute()

@opcode
def PUSH(cpu_context: ProcessorContext, instruction: Instruction):
    """Store Multiple Register onto Stack"""
    operands = instruction.operands
    reg_values = operands[0].value
    if not isinstance(reg_values, list):
        raise EmulationError(f"Expected {operands[0].text} to be a register list.")

    _push(cpu_context, reg_values)

#endregion

#region Load/Store Pair


@opcode
def LDP(cpu_context: ProcessorContext, instruction: Instruction):
    """Load Pair"""
    operands = instruction.operands
    value_a = operands[2].value
    data = cpu_context.memory.read(
        operands[2].addr + operands[0].width,
        operands[1].width,
    )
    value_b = int.from_bytes(data, cpu_context.byteorder)

    logger.debug("Load 0x%X into %s", value_a, operands[0].text)
    logger.debug("Load 0x%X into %s", value_b, operands[1].text)

    operands[0].value = value_a
    operands[1].value = value_b


@opcode
def STP(cpu_context: ProcessorContext, instruction: Instruction):
    """Store Pair"""
    operands = instruction.operands
    value_a = operands[0].value
    value_b = operands[1].value

    logger.debug("Store 0x%X and 0x%X into %s", value_a, value_b, operands[2].text)

    operands[2].value = value_a
    cpu_context.memory.write(
        operands[2].addr + operands[0].width,
        value_b.to_bytes(operands[1].width, cpu_context.byteorder),
    )

#endregion

#region Load/Store unprivileged

@opcode
def LDTR(cpu_context: ProcessorContext, instruction: Instruction):
    """Load unprivileged register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STTR(cpu_context: ProcessorContext, instruction: Instruction):
    """Store unprivileged register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Load-Exclusive/Store-Exclusive


@opcode
def LDXR(cpu_context: ProcessorContext, instruction: Instruction):
    """Load Exclusive register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDXP(cpu_context: ProcessorContext, instruction: Instruction):
    """Load Exclusive pair"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STXR(cpu_context: ProcessorContext, instruction: Instruction):
    """Store Exclusive register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STXP(cpu_context: ProcessorContext, instruction: Instruction):
    """Store Exclusive pair"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


#endregion

#region Load-Acquire/Store-Release


@opcode
def LDAPR(cpu_context: ProcessorContext, instruction: Instruction):
    """Load-Acquire RCpc Register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDAPUR(cpu_context: ProcessorContext, instruction: Instruction):
    """Load-Acquire RCpc Register (unscaled)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDAR(cpu_context: ProcessorContext, instruction: Instruction):
    """Load-Acquire Register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STLR(cpu_context: ProcessorContext, instruction: Instruction):
    """Store-Release Register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STLUR(cpu_context: ProcessorContext, instruction: Instruction):
    """Store-Release Register (unscaled)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDAXR(cpu_context: ProcessorContext, instruction: Instruction):
    """Load-Acquire Exclusive register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDAXP(cpu_context: ProcessorContext, instruction: Instruction):
    """Load-Acquire Exclusive pair"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STLXR(cpu_context: ProcessorContext, instruction: Instruction):
    """Store-Release Exclusive register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STLXP(cpu_context: ProcessorContext, instruction: Instruction):
    """Store-Release Exclusive pair"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


#endregion

#region The LoadLOAcquire/StoreLORelease


@opcode
def LDLAR(cpu_context: ProcessorContext, instruction: Instruction):
    """LoadLOAcquire register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STLLR(cpu_context: ProcessorContext, instruction: Instruction):
    """StoreLORelease register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region The Load/Store SIMD and Floating-point Non-temporal pair


@opcode
def LDNP(cpu_context: ProcessorContext, instruction: Instruction):
    """Load pair of scalar SIMD&FP registers"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STNP(cpu_context: ProcessorContext, instruction: Instruction):
    """Store pair of scalar SIMD&FP registers"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


#endregion

#region Load/Store Vector


@opcode
def LD1(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Load single 1-element structure to one lane of one register LD1 (single structure) on page C7-1637
    Load multiple 1-element structures to one register or to two, three, or four consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD2(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Load single 2-element structure to one lane of two consecutive registers LD2 (single structure)
    Load multiple 2-element structures to two consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD3(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Load single 3-element structure to one lane of three consecutive registers
    Load multiple 3-element structures to three consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD4(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Load single 4-element structure to one lane of four consecutive registers
    Load multiple 4-element structures to four consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ST1(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Store single 1-element structure from one lane of one register
    Store multiple 1-element structures from one register, or from two, three, or four consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ST2(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Store single 2-element structure from one lane of two consecutive registers
    Store multiple 2-element structures from two consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ST3(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Store single 3-element structure from one lane of three consecutive registers
    Store multiple 3-element structures from three consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ST4(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Store single 4-element structure from one lane of four consecutive registers
    Store multiple 4-element structures from four consecutive registers
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD1R(cpu_context: ProcessorContext, instruction: Instruction):
    """Load single 1-element structure and replicate to all lanes of one register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD2R(cpu_context: ProcessorContext, instruction: Instruction):
    """Load single 2-element structure and replicate to all lanes of two registers"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD3R(cpu_context: ProcessorContext, instruction: Instruction):
    """Load single 3-element structure and replicate to all lanes of three registers"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LD4R(cpu_context: ProcessorContext, instruction: Instruction):
    """Load single 4-element structure and replicate to all lanes of four registers"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Compare and Swap


@opcode
def CAS(cpu_context: ProcessorContext, instruction: Instruction):
    """Compare and swap"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CASP(cpu_context: ProcessorContext, instruction: Instruction):
    """Compare and swap pair"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


#endregion

#region Atomic memory operations


@opcode
def LDADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic add"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDCLR(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic bit clear"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDEOR(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic exclusive OR"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDSET(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic bit set"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDMAX(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic signed maximum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDMIN(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic signed minimum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDUMAX(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic unsigned maximum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LDUMIN(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic unsigned minimum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic add, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STCLR(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic bit clear, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STEOR(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic exclusive OR, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STSET(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic bit set, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STMAX(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic signed maximum, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STMIN(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic signed minimum, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STUMAX(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic unsigned maximum, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def STUMIN(cpu_context: ProcessorContext, instruction: Instruction):
    """Atomic unsigned minimum, without return"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


#endregion

#region Swap


@opcode
def SWP(cpu_context: ProcessorContext, instruction: Instruction):
    """Swap"""
    operands = instruction.operands
    value_b = operands[1].value
    value_c = operands[2].value

    logger.debug("Swap %s %s %s", operands[0].text, operands[1].text, operands[2].text)

    operands[0].value = value_c
    operands[2].value = value_b


#endregion

#region Arithmetic (immediate)


@opcode("add")
@opcode("adc")
def ADD(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Handle both ADC and ADD here since the only difference is the flags.
    """
    operands = instruction.operands
    term_1 = operands[-2].value
    term_2 = operands[-1].value
    result = term_1 + term_2
    if instruction.root_mnem.startswith("adc"):
        result += cpu_context.registers.c

    width = get_max_operand_size(operands)
    mask = utils.get_mask(width)

    if instruction.flag_update:
        cpu_context.registers.c = int(result > mask)
        cpu_context.registers.z = int(result & mask == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.registers.v = int(utils.sign_bit(~(term_1 ^ term_2) & (term_2 ^ result), width) == 0)
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n", "v"], operands)

    result = result & mask

    logger.debug("0x%X + 0x%X = 0x%X", term_1, term_2, result)
    operands[0].value = result


# TODO: Due to simplification, it may be better to just keep the opcodes separate.
@opcode("sub")
@opcode("sbc")
@opcode("rsb")
@opcode("rsc")
def SUB(cpu_context: ProcessorContext, instruction: Instruction):
    """Subtract"""
    operands = instruction.operands
    term_1 = operands[1].value
    term_2 = operands[2].value
    if instruction.mnem.startswith("r"):  # reverse subtract
        term_1, term_2 = term_2, term_1

    result = term_1 - term_2
    if instruction.mnem.startswith(("sbc", "rsc")):
        result -= cpu_context.registers.c ^ 1

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        mask = utils.get_mask(width)
        cpu_context.registers.c = int((term_1 & mask) < (term_2 & mask))
        cpu_context.registers.z = int(result & mask == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.registers.v = int(utils.sign_bit((term_1 ^ term_2) & (term_1 ^ result), width) == 0)
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n", "v"], operands)

    logger.debug("0x%X - 0x%X = 0x%X", term_1, term_2, result)
    operands[0].value = result


@opcode
def CMP(cpu_context: ProcessorContext, instruction: Instruction):
    """Compare"""
    operands = instruction.operands
    term_1 = operands[0].value
    term_2 = operands[1].value
    result = term_1 - term_2
    width = get_max_operand_size(operands)

    # Flags are always updated for CMP
    mask = utils.get_mask(width)
    cpu_context.registers.c = int((term_1 & mask) < (term_2 & mask))
    cpu_context.registers.z = int(result & mask == 0)
    cpu_context.registers.n = utils.sign_bit(result, width)
    cpu_context.registers.v = int(utils.sign_bit((term_1 ^ term_2) & (term_1 ^ result), width) == 0)
    cpu_context.jcccontext.update_flag_opnds(["c", "z", "n", "v"], operands)

    logger.debug("0x%X <-> 0x%X = 0x%X", term_1, term_2, result)


@opcode
def CMN(cpu_context: ProcessorContext, instruction: Instruction):
    """Compare negative"""
    operands = instruction.operands
    value_a = operands[1].value
    value_b = operands[2].value
    result = value_a + value_b
    width = get_max_operand_size(operands)

    mask = utils.get_mask(width)
    cpu_context.registers.c = int(result > mask)
    cpu_context.registers.z = int(result & mask == 0)
    cpu_context.registers.n = utils.sign_bit(result, width)
    cpu_context.registers.v = int(utils.sign_bit(~(value_a ^ value_b) & (value_b ^ result), width) == 0)
    cpu_context.jcccontext.update_flag_opnds(["c", "z", "n", "v"], operands)

    logger.debug("0x%X <-> 0x%X = 0x%X", value_a, value_b, result)


#endregion

#region Logical (immediate)


@opcode
def AND(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitwise AND"""
    operands = instruction.operands
    opvalue2 = operands[1].value
    opvalue3 = operands[2].value
    result = opvalue2 & opvalue3

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    logger.debug("0x%X & 0x%X = 0x%X", opvalue2, opvalue3, result)
    operands[0].value = result


def TST(cpu_context: ProcessorContext, instruction: Instruction):
    """Test bits (same as ANDS, but result is discarded)"""
    operands = instruction.operands
    opvalue2 = operands[1].value
    opvalue3 = operands[2].value
    result = opvalue2 & opvalue3

    width = get_max_operand_size(operands)
    cpu_context.registers.z = int(result == 0)
    cpu_context.registers.n = utils.sign_bit(result, width)
    cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    logger.debug("0x%X & 0x%X = 0x%X", opvalue2, opvalue3, result)


@opcode
def EOR(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitwise exclusive OR"""
    operands = instruction.operands
    opvalue2 = operands[1].value
    opvalue3 = operands[2].value
    result = opvalue2 ^ opvalue3

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    logger.debug("0x%X ^ 0x%X = 0x%X", opvalue2, opvalue3, result)
    operands[0].value = result


@opcode
def TEQ(cpu_context: ProcessorContext, instruction: Instruction):
    """Test Equivalence (same as EORS, except the result is discarded)"""
    operands = instruction.operands
    opvalue2 = operands[1].value
    opvalue3 = operands[2].value
    result = opvalue2 ^ opvalue3

    width = get_max_operand_size(operands)
    cpu_context.registers.z = int(result == 0)
    cpu_context.registers.n = utils.sign_bit(result, width)
    cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    logger.debug("0x%X ^ 0x%X = 0x%X", opvalue2, opvalue3, result)


@opcode
def ORR(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitwise inclusive OR"""
    operands = instruction.operands
    opvalue2 = operands[1].value
    opvalue3 = operands[2].value
    result = opvalue2 | opvalue3

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    logger.debug("0x%X | 0x%X = 0x%X", opvalue2, opvalue3, result)
    operands[0].value = result

#endregion

#region Move (wide immediate)


@opcode("mov")
@opcode("movz")
@opcode("cpy")
def MOV(cpu_context: ProcessorContext, instruction: Instruction):
    """Move wide with zero"""
    operands = instruction.operands
    result = operands[1].value

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    operands[0].value = result


@opcode
def MOVN(cpu_context: ProcessorContext, instruction: Instruction):
    """Move wide with NOT"""
    operands = instruction.operands
    result = ~operands[1].value

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    operands[0].value = result


@opcode
def MOVK(cpu_context: ProcessorContext, instruction: Instruction):
    """Move wide with keep"""
    operands = instruction.operands

    # TODO: Is it always lsl?
    shift_mask = {
        0: 0xFFFFFFFFFFFF0000,
        16: 0xFFFFFFFF0000FFFF,
        32: 0xFFFF0000FFFFFFFF,
        48: 0x0000FFFFFFFFFFFF,
    }[operands[1].shift_count]
    operands[0].value = (operands[0].value & shift_mask) | operands[1].value


#endregion

#region PC-relative address calculation


@opcode
def ADRP(cpu_context: ProcessorContext, instruction: Instruction):
    """Compute address of 4KB page at a PC-relative offset"""
    operands = instruction.operands
    pc = cpu_context.registers.pc
    pc = pc & 0xFFFFFFFFFFFFF000  # Zero out bottom 12 bits of PC
    opvalue2 = operands[1].value
    result = pc + 0x1000*opvalue2

    logger.debug("0x%X + 0x1000*0x%X = 0x%X", pc, opvalue2, result)
    operands[0].value = result


@opcode
def ADR(cpu_context: ProcessorContext, instruction: Instruction):
    """Compute address of label at a PC-relative offset."""
    operands = instruction.operands
    pc = cpu_context.registers.pc
    opvalue2 = operands[1].value
    result = pc + opvalue2

    logger.debug("0x%X + 0x%X = 0x%X", pc, opvalue2, result)
    operands[0].value = result

#endregion

#region Bitfield move


@opcode
def BFM(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitfield move"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SBFM(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed bitfield move"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UBFM(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned bitfield move (32-bit)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Bitfield insert and extract


@opcode
def BFC(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitfield insert clear"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def BFI(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitfield insert"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def BFXIL(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitfield extract and insert low"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SBFIZ(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed bitfield insert in zero"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SBFX(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed bitfield extract"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UBFIZ(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned bitfield insert in zero"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UBFX(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned bitfield extract"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


#endregion

#region Extract register


@opcode
def EXTR(cpu_context: ProcessorContext, instruction: Instruction):
    """Extract register from pair"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


#endregion

#region Shift (immediate)


@opcode
def ASR(cpu_context: ProcessorContext, instruction: Instruction):
    """Arithmetic shift right"""
    operands = instruction.operands
    value = operands[1].value
    count = operands[2].value

    width = get_max_operand_size(operands)
    carry, result = arm_utils.asr(value, count, width=width)

    if instruction.flag_update:
        if count:  # C register is unaffected if the shift value is 0
            cpu_context.registers.c = carry
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n"], operands)

    logger.debug("(0x%X >> 0x%X) = 0x%X", value, count, result)
    operands[0].value = result


@opcode
def LSL(cpu_context: ProcessorContext, instruction: Instruction):
    """Logical shift left"""
    operands = instruction.operands
    value = operands[1].value
    count = operands[2].value

    width = get_max_operand_size(operands)
    carry, result = arm_utils.lsl(value, count, width=width)

    if instruction.flag_update:
        if count:
            cpu_context.registers.c = carry
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n"], operands)

    logger.debug("(0x%X << 0x%X) = 0x%X", value, count, result)
    operands[0].value = result


@opcode
def LSR(cpu_context: ProcessorContext, instruction: Instruction):
    """Logical shift right"""
    operands = instruction.operands
    value = operands[1].value
    count = operands[2].value

    width = get_max_operand_size(operands)
    carry, result = arm_utils.lsr(value, count, width=width)

    if instruction.flag_update:
        if count:
            cpu_context.registers.c = carry
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n"], operands)

    logger.debug("(0x%X >> 0x%X) = 0x%X", value, count, result)
    operands[0].value = result


@opcode
def ROR(cpu_context: ProcessorContext, instruction: Instruction):
    """Rotate right"""
    operands = instruction.operands
    value = operands[1].value
    count = operands[2].value

    width = get_max_operand_size(operands)
    carry, result = arm_utils.ror(value, count, width=width)

    if instruction.flag_update:
        if count:
            cpu_context.registers.c = carry
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n"], operands)

    logger.debug("(0x%X ror 0x%X) = 0x%X", value, count, result)
    operands[0].value = result


@opcode
def EOR(cpu_context: ProcessorContext, instruction: Instruction):
    """XOR operands"""
    operands = instruction.operands
    result = operands[1].value ^ operands[2].value

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    operands[0].value = result


#endregion

#region Sign-extend and Zero-extend


@opcode
def SXT(cpu_context: ProcessorContext, instruction: Instruction):
    """Sign-extend"""
    operands = instruction.operands
    operands[0].value = utils.sign_extend(operands[1].value & 0xffff, 2, 4)


@opcode
def UXT(cpu_context: ProcessorContext, instruction: Instruction):
    """Zero-extend"""
    operands = instruction.operands
    operands[0].value = operands[1].value & 0xffff


#endregion

#region Arithmetic (shifted register)


@opcode("neg")
@opcode("ngc")
def NEG(cpu_context: ProcessorContext, instruction: Instruction):
    """Negate (and set flags)"""
    operands = instruction.operands
    value = operands[1].value
    if instruction.root_mnem == "ngc":
        value += int(not cpu_context.registers.c)

    result = -value

    if instruction.flag_update:
        width = operands[1].width
        mask = utils.get_mask(width)
        cpu_context.registers.c = int(result & mask != 0)
        cpu_context.registers.z = int(result & mask == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.registers.v = int(utils.sign_bit(value, width) and not utils.sign_bit(result, width))
        cpu_context.jcccontext.update_flag_opnds(["c", "z", "n", "v"], operands)

    logger.debug("-0x%X -> 0x%X -> %s", value, result, operands[0].text)
    operands[0].value = result

#endregion

#region Flag manipulation instructions


@opcode
def CFINV(cpu_context: ProcessorContext, instruction: Instruction):
    """Invert value of the PSTATE.C bit"""
    cpu_context.registers.c = int(not cpu_context.registers.c)


@opcode
def RMIF(cpu_context: ProcessorContext, instruction: Instruction):
    """Rotate, mask insert flags"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SETF8(cpu_context: ProcessorContext, instruction: Instruction):
    """Evaluation of 8-bit flags"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SETF16(cpu_context: ProcessorContext, instruction: Instruction):
    """Evaluation of 16-bit flags SETF8,"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


#endregion

#region Logical (shifted register)


@opcode
def BIC(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitwise bit clear"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def BICS(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitwise bit clear and set flags"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def EON(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitwise exclusive OR NOT"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MVN(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitwise NOT"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ORN(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitwise inclusive OR NOT"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Shift (register)


@opcode
def ASRV(cpu_context: ProcessorContext, instruction: Instruction):
    """Arithmetic shift right variable"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LSLV(cpu_context: ProcessorContext, instruction: Instruction):
    """Logical shift left variable"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def LSRV(cpu_context: ProcessorContext, instruction: Instruction):
    """Logical shift right variable"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RORV(cpu_context: ProcessorContext, instruction: Instruction):
    """Rotate right variable"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


#endregion

#region Multiply

@opcode
def MADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Multiply-add"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MSUB(cpu_context: ProcessorContext, instruction: Instruction):
    """Multiply-subtract"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MNEG(cpu_context: ProcessorContext, instruction: Instruction):
    """Multiply-negate"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MUL(cpu_context: ProcessorContext, instruction: Instruction):
    """Multiply"""
    operands = instruction.operands
    term_1 = operands[1].value
    term_2 = operands[2].value
    result = term_1 * term_2

    if instruction.flag_update:
        width = get_max_operand_size(operands)
        cpu_context.registers.z = int(result == 0)
        cpu_context.registers.n = utils.sign_bit(result, width)
        cpu_context.jcccontext.update_flag_opnds(["z", "n"], operands)

    logger.debug("0x%X * 0x%X = 0x%X", term_1, term_2, result)
    operands[0].value = result


@opcode
def SMADDL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed multiply-add long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMSUBL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed multiply-subtract long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMNEGL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed multiply-negate long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMULL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed multiply long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMULH(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed multiply high"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMADDL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned multiply-add long"""
    operands = instruction.operands
    opvalue2 = operands[1].value
    opvalue3 = operands[2].value
    opvalue4 = operands[3].value
    result = (opvalue2 * opvalue3) + opvalue4

    logger.debug("(0x%X * 0x%X) + 0x%X = 0x%X", opvalue2, opvalue2, opvalue4, result)
    operands[0].value = result


@opcode
def UMSUBL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned multiply-subtract long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMNEGL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned multiply-negate long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMULL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned multiply long"""
    operands = instruction.operands
    term_1 = operands[-2].value
    term_2 = operands[-1].value
    result = term_1 * term_2

    logger.debug("0x%X * 0x%X = 0x%X", term_1, term_2, result)

    if len(operands) > 3:
        operands[0].value = result & 0xffffffff
        operands[1].value = (result >> 32) & 0xffffffff
    else:
        operands[0].value = result


@opcode
def UMULH(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned multiply high"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Divide


@opcode
def SDIV(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed divide"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UDIV(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned divide"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region CRC32


@opcode
def CRC32(cpu_context: ProcessorContext, instruction: Instruction):
    """CRC-32 sum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CRC32C(cpu_context: ProcessorContext, instruction: Instruction):
    """CRC-32C sum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

# region Bit operation


@opcode
def CLS(cpu_context: ProcessorContext, instruction: Instruction):
    """Count leading sign bits"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CLZ(cpu_context: ProcessorContext, instruction: Instruction):
    """Count leading zero bits"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RBIT(cpu_context: ProcessorContext, instruction: Instruction):
    """Reverse bit order"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def REV(cpu_context: ProcessorContext, instruction: Instruction):
    """Reverse bytes in register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def REV16(cpu_context: ProcessorContext, instruction: Instruction):
    """Reverse bytes in halfwords"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def REV32(cpu_context: ProcessorContext, instruction: Instruction):
    """Reverses bytes in words"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def REV64(cpu_context: ProcessorContext, instruction: Instruction):
    """Reverse bytes in register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Conditional select


@opcode
def CSEL(cpu_context: ProcessorContext, instruction: Instruction):
    """Conditional select"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CSINC(cpu_context: ProcessorContext, instruction: Instruction):
    """Conditional select increment"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CSINV(cpu_context: ProcessorContext, instruction: Instruction):
    """Conditional select inversion"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CSNEG(cpu_context: ProcessorContext, instruction: Instruction):
    """Conditional select negation"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CSET(cpu_context: ProcessorContext, instruction: Instruction):
    """Conditional set"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CSETM(cpu_context: ProcessorContext, instruction: Instruction):
    """Conditional set mask"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CINC(cpu_context: ProcessorContext, instruction: Instruction):
    """Conditional increment"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CINV(cpu_context: ProcessorContext, instruction: Instruction):
    """Conditional invert"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CNEG(cpu_context: ProcessorContext, instruction: Instruction):
    """Conditional negate"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Conditional comparison


@opcode
def CCMN(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Conditional compare negative (register)
    Conditional compare negative (immediate)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CCMP(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Conditional compare (register)
    Conditional compare (immediate)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Floating-point move (register)


@opcode
def FMOV(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Floating-point move register without conversion
    Floating-point move to or from general-purpose register without conversion
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Convert floating-point precision

@opcode
def FCVT(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point convert precision (scalar)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Convert between floating-point and integer or fixed-point


@opcode
def FCVTAS(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar convert to signed integer, rounding to nearest with ties to away (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTAU(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar convert to unsigned integer, rounding to nearest with ties to away (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTMS(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar convert to signed integer, rounding toward minus infinity (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTMU(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar convert to unsigned integer, rounding toward minus infinity (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTNS(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar convert to signed integer, rounding to nearest with ties to even (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTNU(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar convert to unsigned integer, rounding to nearest with ties to even (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTPS(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar convert to signed integer, rounding toward positive infinity (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTPU(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar convert to unsigned integer, rounding toward positive infinity (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTZS(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Floating-point scalar convert to signed integer, rounding toward zero (scalar form)
    Floating-point scalar convert to signed fixed-point, rounding toward zero (scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTZU(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Floating-point scalar convert to unsigned integer, rounding toward zero (scalar form)
    Floating-point scalar convert to unsigned fixed-point, rounding toward zero (scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FJCVTZS(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point Javascript convert to signed fixed-point, rounding toward zero"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SCVTF(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Signed integer scalar convert to floating-point, using the current rounding mode (scalar form)
    Signed integer fixed-point convert to floating-point, using the current rounding mode (scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UCVTF(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Unsigned integer scalar convert to floating-point, using the current rounding mode (scalar form)
    Unsigned integer fixed-point convert to floating-point, using the current rounding mode (scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Floating-point round to integer


@opcode
def FRINTA(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point round to integer, to nearest with ties to away"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRINTI(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point round to integer, using current rounding mode"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRINTM(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point round to integer, toward minus infinity"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRINTN(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point round to integer, to nearest with ties to even"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRINTP(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point round to integer, toward positive infinity"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRINTX(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point round to integer exact, using current rounding mode"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRINTZ(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point round to integer, toward zero"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Floating-point multiply-add


@opcode
def FMADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar fused multiply-add"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMSUB(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar fused multiply-subtract"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FNMADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar negated fused multiply-add"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FNMSUB(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar negated fused multiply-subtract"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Floating-point arithmetic (one source)


@opcode
def FABS(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar absolute value"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FNEG(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar negate"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FSQRT(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar square root"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Floating-point arithmetic (two sources)


@opcode
def FADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar add"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FDIV(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar divide"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMUL(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar multiply"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FNMUL(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar multiply-negate"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FSUB(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar subtract"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Floating-point minimum and maximum


@opcode
def FMAX(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar maximum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMAXNM(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar maximum number"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMIN(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar minimum"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMINNM(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar minimum number"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Floating-point comparison


@opcode
def FCMP(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point quiet compare"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMPE(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point signaling compare"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCCMP(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point conditional quiet compare"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCCMPE(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point conditional signaling compare"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region Floating-point conditional select


@opcode
def FCSEL(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point scalar conditional select"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD move


@opcode
def DUP(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Duplicate vector element to vector or scalar
    Duplicate general-purpose register to vector
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def INSa(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Insert vector element from another vector element
    Insert vector element from general-purpose register INS (general) on page C7-16
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMOV(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned move vector element to general-purpose register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMOV(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed move vector element to general-purpose register"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD arithmetic


@opcode
def BIF(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitwise insert if false (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def BIT(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitwise insert if true (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def BSL(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitwise select (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FABD(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point absolute difference (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMLA(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point fused multiply-add (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMLAL(cpu_context: ProcessorContext, instruction: Instruction):
    """FMLAL2 Floating-point fused multiply-add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMLS(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point fused multiply-subtract (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMLSL(cpu_context: ProcessorContext, instruction: Instruction):
    """FMLSL2 Floating-point fused multiply-subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMULX(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point multiply extended (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRECPS(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point reciprocal step (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRSQRTS(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point reciprocal square root step (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MLA(cpu_context: ProcessorContext, instruction: Instruction):
    """Multiply-add (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MLS(cpu_context: ProcessorContext, instruction: Instruction):
    """Multiply-subtract (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def PMUL(cpu_context: ProcessorContext, instruction: Instruction):
    """Polynomial multiply (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SABA(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed absolute difference and accumulate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SABD(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed absolute difference (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed halving add (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHSUB(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed halving subtract (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMAX(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed maximum (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMIN(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed minimum (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating add (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMULH(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating doubling multiply returning high half (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRSHL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating rounding shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRDMLAH(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating rounding doubling multiply accumulate returning high half"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRDMLSH(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating rounding doubling multiply subtract returning high half"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRDMULH(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating rounding doubling multiply returning high half (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSHL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSUB(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating subtract (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SRHADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed rounding halving add (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SRSHL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed rounding shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSHL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UABA(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned absolute difference and accumulate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UABD(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned absolute difference (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UHADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned halving add (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UHSUB(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned halving subtract (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMAX(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned maximum (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMIN(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned minimum (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned saturating add (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQRSHL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned saturating rounding shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQSHL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned saturating shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQSUB(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned saturating subtract (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def URHADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned rounding halving add (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def URSHL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned rounding shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USHL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned shift left (register) (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD compare


@opcode
def CMEQ(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Compare bitwise equal (vector and scalar form)
    Compare bitwise equal to zero (vector and scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMHS(cpu_context: ProcessorContext, instruction: Instruction):
    """Compare unsigned higher or same (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMGE(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Compare signed greater than or equal (vector and scalar form)
    Compare signed greater than or equal to zero (vector and scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMHI(cpu_context: ProcessorContext, instruction: Instruction):
    """Compare unsigned higher (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMGT(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Compare signed greater than (vector and scalar form)
    Compare signed greater than zero (vector and scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMLE(cpu_context: ProcessorContext, instruction: Instruction):
    """Compare signed less than or equal to zero (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMLT(cpu_context: ProcessorContext, instruction: Instruction):
    """Compare signed less than zero (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CMTST(cpu_context: ProcessorContext, instruction: Instruction):
    """Compare bitwise test bits nonzero (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMEQ(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Floating-point compare equal (vector and scalar form)
    Floating-point compare equal to zero (vector and scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMGE(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Floating-point compare greater than or equal (vector and scalar form)
    Floating-point compare greater than or equal to zero (vector and scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMGT(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Floating-point compare greater than (vector and scalar form)
    Floating-point compare greater than zero (vector and scalar form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMLE(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point compare less than or equal to zero (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMLT(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point compare less than zero (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FACGE(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point absolute compare greater than or equal (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FACGT(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point absolute compare greater than (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD widening and narrowing arithmetic


@opcode
def ADDHN(cpu_context: ProcessorContext, instruction: Instruction):
    """Add returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ADDHN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Add returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def PMULL(cpu_context: ProcessorContext, instruction: Instruction):
    """Polynomial multiply long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def PMULL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Polynomial multiply long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RADDHN(cpu_context: ProcessorContext, instruction: Instruction):
    """Rounding add returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RADDHN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Rounding add returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RSUBHN(cpu_context: ProcessorContext, instruction: Instruction):
    """Rounding subtract returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RSUBHN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Rounding subtract returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SABAL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed absolute difference and accumulate long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SABAL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed absolute difference and accumulate long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SABDL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed absolute difference long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SABDL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed absolute difference long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADDL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADDL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADDW(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed add wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADDW2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed add wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMLAL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed multiply-add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMLAL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed multiply-add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMLSL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed multiply-subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMLSL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed multiply-subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMULL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed multiply long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMLAL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating doubling multiply-add long (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMLAL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating doubling multiply-add long (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMLSL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating doubling multiply-subtract long (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMLSL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating doubling multiply-subtract long (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMULL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating doubling multiply long (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQDMULL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating doubling multiply long (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSUBL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSUBL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSUBW(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed subtract wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSUBW2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed subtract wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SUBHN(cpu_context: ProcessorContext, instruction: Instruction):
    """Subtract returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SUBHN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Subtract returning high, narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UABAL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned absolute difference and accumulate long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UABAL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned absolute difference and accumulate long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UABDL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned absolute difference long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UABDL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned absolute difference long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADDL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADDL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADDW(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned add wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADDW2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned add wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMLAL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned multiply-add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMLAL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned multiply-add long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMLSL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned multiply-subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMLSL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned multiply-subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMULL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned multiply long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USUBL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USUBL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned subtract long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USUBW(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned subtract wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USUBW2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned subtract wide (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD unary arithmetic


@opcode
def ABS(cpu_context: ProcessorContext, instruction: Instruction):
    """Absolute value (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def CNT(cpu_context: ProcessorContext, instruction: Instruction):
    """Population count per byte (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTL(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point convert to higher precision long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point convert to higher precision long (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTN(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point convert to lower precision narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point convert to lower precision narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTXN(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point convert to lower precision narrow, rounding to odd (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCVTXN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point convert to lower precision narrow, rounding to odd (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRECPE(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point reciprocal estimate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRECPX(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point reciprocal square root (scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FRSQRTE(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point reciprocal square root estimate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def NOT(cpu_context: ProcessorContext, instruction: Instruction):
    """Bitwise"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADALP(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed add and accumulate long pairwise (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADDLP(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed add long pairwise (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQABS(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating absolute value (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQNEG(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating negate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQXTN(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating extract narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQXTN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating extract narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQXTUN(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating extract unsigned narrow (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQXTUN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating extract unsigned narrow (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SUQADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating accumulate of unsigned value (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SXTL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed extend long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SXTL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed extend long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADALP(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned add and accumulate long pairwise (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADDLP(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned add long pairwise (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQXTN(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned saturating extract narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQXTN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned saturating extract narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def URECPE(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned reciprocal estimate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def URSQRTE(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned reciprocal square root estimate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USQADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned saturating accumulate of signed value (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UXTL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned extend long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UXTL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned extend long"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def XTN(cpu_context: ProcessorContext, instruction: Instruction):
    """Extract narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def XTN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Extract narrow (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD by element arithmetic


@opcode
def FMLAL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point fused multiply-add long (vector form) FMLAL,"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMLSL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point fused multiply-subtract long (vector form) FMLSL,"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD permute


@opcode
def EXT(cpu_context: ProcessorContext, instruction: Instruction):
    """Extract vector from a pair of vectors"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def TRN1(cpu_context: ProcessorContext, instruction: Instruction):
    """Transpose vectors (primary)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def TRN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Transpose vectors (secondary)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UZP1(cpu_context: ProcessorContext, instruction: Instruction):
    """Unzip vectors (primary)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UZP2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unzip vectors (secondary)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ZIP1(cpu_context: ProcessorContext, instruction: Instruction):
    """Zip vectors (primary)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def ZIP2(cpu_context: ProcessorContext, instruction: Instruction):
    """Zip vectors (secondary)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD immediate


@opcode
def MOVI(cpu_context: ProcessorContext, instruction: Instruction):
    """Move immediate"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def MVNI(cpu_context: ProcessorContext, instruction: Instruction):
    """Move inverted immediate"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD shift (immediate)


@opcode
def RSHRN(cpu_context: ProcessorContext, instruction: Instruction):
    """Rounding shift right narrow immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def RSHRN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Rounding shift right narrow immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHL(cpu_context: ProcessorContext, instruction: Instruction):
    """Shift left immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHLL(cpu_context: ProcessorContext, instruction: Instruction):
    """Shift left long (by element size) (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHLL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Shift left long (by element size) (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHRN(cpu_context: ProcessorContext, instruction: Instruction):
    """Shift right narrow immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SHRN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Shift right narrow immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SLI(cpu_context: ProcessorContext, instruction: Instruction):
    """Shift left and insert immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRSHRN(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating rounded shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRSHRN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating rounded shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRSHRUN(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating shift right unsigned narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQRSHRUN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating shift right unsigned narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSHLU(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating shift left unsigned immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSHRN(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSHRN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSHRUN(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating shift right unsigned narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SQSHRUN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed saturating shift right unsigned narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SRI(cpu_context: ProcessorContext, instruction: Instruction):
    """Shift right and insert immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SRSHR(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed rounding shift right immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SRSRA(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed rounding shift right and accumulate immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSHLL(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed shift left long immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSHLL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed shift left long immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSHR(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed shift right immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SSRA(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed integer shift right and accumulate immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQRSHRN(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned saturating rounded shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQRSHRN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned saturating rounded shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQSHRN(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned saturating shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UQSHRN2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned saturating shift right narrow immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def URSHR(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned rounding shift right immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def URSRA(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned integer rounding shift right and accumulate immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USHLL(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned shift left long immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USHLL2(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned shift left long immediate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USHR(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned shift right immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def USRA(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned shift right and accumulate immediate (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD reduce (across vector lanes)


@opcode
def ADDV(cpu_context: ProcessorContext, instruction: Instruction):
    """Add (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMAXNMV(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point maximum number (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMAXV(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point maximum (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMINNMV(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point minimum number (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMINV(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point minimum (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SADDLV(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed add long (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMAXV(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed maximum (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMINV(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed minimum (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UADDLV(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned add long (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMAXV(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned maximum (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMINV(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned minimum (across vector)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD pairwise arithmetic


@opcode
def ADDP(cpu_context: ProcessorContext, instruction: Instruction):
    """Add pairwise (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FADDP(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point add pairwise (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMAXNMP(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point maximum number pairwise (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMAXP(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point maximum pairwise (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMINNMP(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point minimum number pairwise (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FMINP(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point minimum pairwise (vector and scalar form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMAXP(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed maximum pairwise"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def SMINP(cpu_context: ProcessorContext, instruction: Instruction):
    """Signed minimum pairwise"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMAXP(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned maximum pairwise"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UMINP(cpu_context: ProcessorContext, instruction: Instruction):
    """Unsigned minimum pairwise"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD dot product


@opcode
def SDOT(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Signed dot product (vector form)
    Signed dot product (indexed form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def UDOT(cpu_context: ProcessorContext, instruction: Instruction):
    """
    Unsigned dot product (vector form)
    Unsigned dot product (indexed form)
    """
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD table lookup


@opcode
def TBL(cpu_context: ProcessorContext, instruction: Instruction):
    """Table vector lookup"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def TBX(cpu_context: ProcessorContext, instruction: Instruction):
    """Table vector lookup extension"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)

#endregion

#region SIMD complex number arithmetic


@opcode
def FCADD(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point complex add"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


@opcode
def FCMLA(cpu_context: ProcessorContext, instruction: Instruction):
    """Floating-point complex multiply accumulate (vector form)"""
    logger.debug("%s instruction not currently implemented.", instruction.mnem)


#endregion

#region Global helper functions


# TODO: Move to Instruction.
def get_max_operand_size(operands):
    """
    Given the list of named tuples containing the operand value and bit width, determine the largest bit width.

    :param operands: list of Operand objects

    :return: largest operand width
    """
    return max(operand.width for operand in operands)

#endregion
