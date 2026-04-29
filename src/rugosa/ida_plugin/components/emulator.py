
from __future__ import annotations

import traceback
from typing import TYPE_CHECKING, Optional

from PyQt5 import QtWidgets, QtCore

import ida_kernwin

import dragodis
import rugosa
from rugosa.ida_plugin.gui.emulator import Ui_EmulatorForm
from rugosa.ida_plugin.components import (
    Operands, Registers, Memory, Variables, FunctionArguments, CallHistory, Actions, Stdout
)

if TYPE_CHECKING:
    from rugosa.emulation.cpu_context import ProcessorContext


class EmulatorForm(Ui_EmulatorForm, ida_kernwin.PluginForm):

    def __init__(self, dis: dragodis.Disassembler):
        super().__init__()
        self._ctx: Optional[ProcessorContext] = None
        self._call_stack = []
        self.emulator = rugosa.Emulator(dis)

    def setupUi(self, form):
        super().setupUi(form)
        # Remove placeholder text.
        self.instruction.setText("")
        self.status.setText("")
        self.function_signature.setText("")

        self.operands = Operands(self)
        self.registers = Registers(self)
        self.memory = Memory(self)
        self.variables = Variables(self)
        self.function_arguments = FunctionArguments(self)
        self.call_history = CallHistory(self)
        self.actions = Actions(self)
        self.stdout = Stdout(self)

        self.instruction.mousePressEvent = self.jump_instruction

        self.run_button.clicked.connect(self.run)
        self.step_over_button.clicked.connect(self.step_over)
        # TODO: Add support for these after refactoring ProcessorContext.
        # self.step_into_button.clicked.connect(self.step_into)
        # self.step_out_button.clicked.connect(self.step_out)

    def OnCreate(self, form):
        """
        Called when the widget is created
        """
        form = self.FormToPyQtWidget(form)
        self.setupUi(form)
        self.parent = form

    def show_exception(self, exception: Exception, title="Error"):
        """
        Shows exception in dialog box.
        """
        dlg = QtWidgets.QMessageBox(self.parent)
        dlg.setIcon(QtWidgets.QMessageBox.Critical)
        dlg.setWindowTitle(title)
        dlg.setText(str(exception))
        details = "\n".join(traceback.format_tb(exception.__traceback__))
        dlg.setDetailedText(details)
        dlg.exec()

    def jump_instruction(self, evt):
        if self._ctx:
            ida_kernwin.jumpto(self._ctx.ip)

    def redirect(self, item: QtWidgets.QTableWidgetItem):
        try:
            address = int(item.text(), 16)
        except ValueError:
            return
        ida_kernwin.jumpto(address)

    def enable_emulator_controls(self):
        """
        Enable emulator buttons based on current context.
        """
        if not self._ctx:
            self.reset()
            return

        self.tabs.setEnabled(True)
        self.step_over_button.setEnabled(True)
        # TODO: Add support for these after some refactoring of ProcessorContext.
        # self.step_into_button.setEnabled(self._ctx.instruction.is_call)
        # self.step_out_button.setEnabled(bool(self._call_stack))

    def update(self):
        """
        Updates UI based on current context.
        """
        ctx = self._ctx
        if not ctx:
            return

        # Enable controls.
        self.enable_emulator_controls()

        insn = ctx.instruction
        self.instruction.setText(f"0x{ctx.ip:08X}: {insn.text}")

        # Fill in tables
        self.operands.populate(ctx)
        self.registers.populate(ctx)
        self.variables.populate(ctx)
        self.function_arguments.populate(ctx)
        self.memory.populate(ctx)
        self.stdout.populate(ctx)
        self.call_history.populate(ctx)
        self.actions.populate(ctx)

        executed_instructions = ctx.executed_instructions
        if executed_instructions:
            self.status.setText(
                f"Emulated {len(executed_instructions)} instructions: "
                f"{hex(ctx.executed_instructions[0])} -> {hex(executed_instructions[-1])}"
            )
        else:
            self.status.setText(f"Emulated 0 instructions.")

        ida_kernwin.jumpto(ctx.ip)

    def run(self):
        """
        Runs emulation using current settings.
        """
        addr = ida_kernwin.get_screen_ea()
        ida_kernwin.show_wait_box(f"HIDECANCEL\nEmulating instructions up to {hex(addr)}")
        try:
            ctx = self.emulator.context_at(
                addr,
                depth=self.trace_depth.value(),
                call_depth=self.call_depth.value(),
                exhaustive=self.exhaustive.isChecked(),
                follow_loops=self.follow_loops.isChecked(),
            )
        except Exception as e:
            ida_kernwin.hide_wait_box()
            self.show_exception(e, "Failed to emulate")
            return
        finally:
            ida_kernwin.hide_wait_box()
        self._ctx = ctx

        self.update()

    def step_over(self):
        ctx = self._ctx
        if not ctx:
            return
        ctx.execute(call_depth=self.call_depth.value())
        self.update()

    # TODO: Need to generate a way to have the context put us in a state where the call instruction is step
    #   (e.g. stack pointer pushed with return address) but not restored (return address popped and set)
    #   - This probably means emulating the 'ret' opcode.
    # def step_into(self):
    #     ctx = self._ctx
    #     if not ctx:
    #         return
    #     try:
    #         func_address = ctx.get_function_signature().address
    #     except dragodis.NotExistError:
    #         self.step_over()  # step over instead if we fail to get the funciton call.
    #         return
    #     except Exception as e:
    #         self.show_exception(e, "Failed to get function call address")
    #         return
    #
    #     # Save call stack info so we can restore it later.
    #     self._call_stack.append((ctx.instruction.next_ip, ctx._call_depth, ctx._sp_start))
    #     ctx.execute(func_address)
    #
    # def step_out(self):
    #     ...

    def reset(self):
        self._ctx = None
        self._call_stack = []
        self.step_over_button.setEnabled(False)
        self.step_into_button.setEnabled(False)
        self.step_out_button.setEnabled(False)
        self.tabs.setEnabled(False)


if __name__ == "__main__":
    form = EmulatorForm(dragodis.IDA())
    form.Show("Rugosa Emulator")
