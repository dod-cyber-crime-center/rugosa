"""
Interface for instruction management.
"""
import logging

from dragodis import BACKEND_GHIDRA
from dragodis.interface.instruction import ARMConditionCode

from .operands import ARMOperand
from ..exceptions import EmulationError
from ..instruction import Instruction

logger = logging.getLogger(__name__)


class ARMInstruction(Instruction):

    _operand_class = ARMOperand

    # Maps condition code to function to check if we can execute.
    _cond_map = {
        ARMConditionCode.EQ: lambda ctx: bool(ctx.registers.z),
        ARMConditionCode.NE: lambda ctx: bool(not ctx.registers.z),
        ARMConditionCode.CS: lambda ctx: bool(ctx.registers.c),
        ARMConditionCode.CC: lambda ctx: bool(not ctx.registers.c),
        ARMConditionCode.MI: lambda ctx: bool(ctx.registers.n),
        ARMConditionCode.PL: lambda ctx: bool(not ctx.registers.n),
        ARMConditionCode.VS: lambda ctx: bool(ctx.registers.v),
        ARMConditionCode.VC: lambda ctx: bool(not ctx.registers.v),
        ARMConditionCode.HI: lambda ctx: bool(ctx.registers.c and not ctx.registers.z),
        ARMConditionCode.LS: lambda ctx: bool(not ctx.registers.c or ctx.registers.z),
        ARMConditionCode.GE: lambda ctx: bool(
            (ctx.registers.n and ctx.registers.v)
            or (not ctx.registers.n and not ctx.registers.v)
        ),
        ARMConditionCode.LT: lambda ctx: bool(
            (ctx.registers.n and not ctx.registers.v)
            or (not ctx.registers.n and ctx.registers.v)
        ),
        ARMConditionCode.GT: lambda ctx: bool(
            not ctx.registers.z
            and (
                (ctx.registers.n and ctx.registers.v)
                or (not ctx.registers.n and not ctx.registers.v)
            )
        ),
        ARMConditionCode.LE: lambda ctx: bool(
            ctx.registers.z
            or (ctx.registers.n and not ctx.registers.v)
            or (not ctx.registers.n and ctx.registers.v)
        ),
        ARMConditionCode.AL: lambda ctx: True,
        ARMConditionCode.NV: lambda ctx: False,
    }

    @property
    def flag_update(self) -> bool:
        """
        Whether the condition flags are updated on the result of the operation.
        (S postfix)
        """
        return self._insn.update_flags

    def _check_condition(self) -> bool:
        """
        Checks condition flags to determine if instruction should be executed.
        """
        condition = self._insn.condition_code
        try:
            return self._cond_map[condition](self._cpu_context)
        except IndexError:
            raise EmulationError(f"Invalid condition code: {condition}")

    def _execute(self):
        # First check if conditions allow us to execute the instruction.
        if not self._check_condition():
            logger.debug("Skipping instruction at 0x%X. Condition code fails.", self.ip)
            return

        # Execute instruction.
        super()._execute()

        # If post-index or pre-index with update addressing mode,
        # update operand's base register based on offset.
        if self._insn.writeback:
            mnemonic = self._insn.mnemonic

            # Ignore push and pop instructions. We handle that in the opcode hook.
            if mnemonic in ("push", "pop"):
                return

            if "ldm" in mnemonic or "stm" in mnemonic:
                # write back for first operand (LDM/STM instruction)
                operand = self.operands[0]
                # In Ghidra, an stm*/ldm* instruction for push and pop will be treated as having
                # a single operand: sp!,{..}
                # This messes with our ability to update the writeback.
                # In the opcode hook we divert to a push/pop hook, but also need to be sure
                # we don't attempt the writeback here.
                if self._cpu_context.emulator.disassembler.name == BACKEND_GHIDRA and operand.text.startswith("sp!,"):
                    return
            else:
                # write back for last operand (! postfix or post-indexed operand)
                operand = self.operands[-1]

            logger.debug("Writeback operation for: %s", operand.text)
            operand.base += operand.offset
