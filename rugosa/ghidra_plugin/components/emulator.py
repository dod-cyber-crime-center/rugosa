
from __future__ import annotations

import contextlib
import logging
import traceback
from typing import TYPE_CHECKING, Optional

import jpype

RugosaActionListener = jpype.JClass("dc3.rugosa.plugin.RugosaActionListener")
RugosaTask = jpype.JClass("dc3.rugosa.plugin.RugosaTask")

import dragodis
from dragodis.ghidra import GhidraLocal
from ghidra.util import Swing

import rugosa
from rugosa.ghidra_plugin.gui.mouse_listener import MouseListener
from rugosa.ghidra_plugin.gui.program_listener import ProgramListener
from rugosa.ghidra_plugin.gui.context_menu import TableContextMenuEntry
from rugosa.ghidra_plugin.gui.error_msg import show_exception, catch_errors
from rugosa.ghidra_plugin.components.operands import Operands
from rugosa.ghidra_plugin.components.registers import Registers
from rugosa.ghidra_plugin.components.memory import Memory
from rugosa.ghidra_plugin.components.variables import Variables
from rugosa.ghidra_plugin.components.actions import Actions
from rugosa.ghidra_plugin.components.function_arguments import FunctionArguments
from rugosa.ghidra_plugin.components.call_history import CallHistory
from rugosa.ghidra_plugin.components.stdout import Stdout
from rugosa.emulation.cpu_context import ProcessorContext

if TYPE_CHECKING:
    import ghidra
    from dc3.rugosa.plugin import EmulatorForm as JavaEmulatorForm, RugosaPlugin
    from java.awt.event import ActionEvent, MouseEvent
    from javax.swing import JTable

logger = logging.getLogger(__name__)


class EmulatorForm:

    def __init__(self, plugin: RugosaPlugin):
        self.plugin = plugin
        self.program_listener = ProgramListener(self)
        self.plugin.setProgramListener(self.program_listener)

    @property
    def _ctx(self) -> Optional[ProcessorContext]:
        if state := self.program_listener.state:
            return state.ctx

    @property
    def dis(self) -> GhidraLocal:
        if state := self.program_listener.state:
            return state.dis

    @property
    def emulator(self) -> rugosa.Emulator:
        if state := self.program_listener.state:
            return state.emulator

    @property
    def state(self) -> ProgramListener:
        return self.program_listener.state

    @catch_errors
    def setupUI(self, form: JavaEmulatorForm):
        self.ui = form
        # Remove placeholder text.
        self.ui.instruction.setText("")
        self.ui.status.setText("")
        self.ui.functionSignature.setText("")

        self.operands = Operands(self)
        self.registers = Registers(self)
        self.memory = Memory(self)
        self.variables = Variables(self)
        self.function_arguments = FunctionArguments(self)
        self.actions = Actions(self)
        self.call_history = CallHistory(self)
        self.stdout = Stdout(self)

        # Hook up action listeners.
        self.ui.instruction.addMouseListener(MouseListener(clicked=self.jump_instruction))
        self.ui.runButton.addActionListener(RugosaActionListener @ self.run)
        self.ui.stepOverButton.addActionListener(RugosaActionListener @ self.step_over)
        # Double-clicking table items should try to redirect disassembly if possible.
        redirect = MouseListener(clicked=self.redirect)
        self.ui.operandsTable.addMouseListener(redirect)
        self.ui.registersTable.addMouseListener(redirect)
        self.ui.variablesTable.addMouseListener(redirect)
        self.ui.functionArgumentsTable.addMouseListener(redirect)
        self.ui.callHistoryTable.addMouseListener(redirect)
        self.ui.actionsSideTable.addMouseListener(redirect)
        self.ui.actionsFieldsTable.addMouseListener(redirect)

    def add_context_menu_entry(self, entry: TableContextMenuEntry):
        self.plugin.addContextMenuEntry(entry.NAME, entry)

    @contextlib.contextmanager
    def transaction(self, message="rugosa transaction"):
        """Some modifications with Ghidra require being in a transaction."""
        t = self.dis._program.startTransaction(message)
        success = False
        try:
            yield
            success = True
        finally:
            self.dis._program.endTransaction(t, success)

    @catch_errors
    def jump_instruction(self, event: MouseEvent):
        state = self.program_listener.state
        if state is None:
            return
        if state.ctx and event.getClickCount() == 2:  # double click
            self.plugin.goTo(state.dis._to_addr(state.ctx.ip))

    @catch_errors
    def redirect(self, event: MouseEvent):
        """Redirects clicks on addresses to the line in the disassembly."""
        dis = self.dis
        if dis is None:
            return
        if event.getClickCount() == 2:
            table: JTable = event.getSource()
            row = table.getSelectedRow()
            col = table.getSelectedColumn()
            value = table.getModel().getValueAt(row, col)
            try:
                address = int(value, 16)
            except ValueError:
                return
            self.plugin.goTo(dis._to_addr(address))

    @catch_errors
    def enable_emulator_controls(self):
        """
        Enable emulator buttons based on current context.
        """
        if not self._ctx:
            self.reset()
            return

        self.ui.tabs.setEnabled(True)
        self.ui.stepOverButton.setEnabled(True)
        # TODO: Add support for these after some refactoring of ProcessorContext.
        # self.ui.stepIntoButton.setEnabled(self._ctx.instruction.is_call)
        # self.ui.stepOutButton.setEnabled(bool(self._call_stack))

    @catch_errors
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
        self.ui.instruction.setText(f"0x{ctx.ip:08X}: {insn.text}")

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
            self.ui.status.setText(
                f"Emulated {len(executed_instructions)} instructions: "
                f"{hex(ctx.executed_instructions[0])} -> {hex(executed_instructions[-1])}"
            )
        else:
            self.ui.status.setText(f"Emulated 0 instructions.")

        self.plugin.goTo(self.dis._to_addr(ctx.ip))

    def _emulate(self, addr):
        with self.transaction():
            try:
                self.state.ctx = self.emulator.context_at(
                    addr,
                    depth=self.ui.traceDepth.getValue(),
                    call_depth=self.ui.callDepth.getValue(),
                    exhaustive=self.ui.exhaustiveCheckBox.isSelected(),
                    follow_loops=self.ui.followLoopsCheckBox.isSelected(),
                )
                Swing.runIfSwingOrRunLater(self.update)
            except dragodis.NotExistError as e:
                # User hasn't selected a valid function.
                show_exception(e, "Invalid Instruction", level=logging.WARNING)

            except Exception as e:
                show_exception(e, "Failed to emulate")

    @catch_errors
    def run(self, event: ActionEvent):
        """
        Runs emulation using current settings.
        """
        addr = self.plugin.getCurrentAddress().getOffset()
        task = RugosaTask("Emulating...", lambda: self._emulate(addr))
        self.plugin.tool.execute(task)

    @catch_errors
    def step_over(self, event: ActionEvent):
        ctx = self._ctx
        if not ctx:
            return
        ctx.execute(call_depth=self.ui.callDepth.getValue())
        self.update()

    def reset(self):
        self._ctx = None
        self.ui.stepOverButton.setEnabled(False)
        self.ui.stepIntoButton.setEnabled(False)
        self.ui.stepOutButton.setEnabled(False)
        self.ui.tabs.setEnabled(False)


def initialize(form: JavaEmulatorForm, plugin: RugosaPlugin):
    """
    Called by Java to initialize Emulator plugin.
    """
    logging.basicConfig(level=logging.DEBUG)
    try:
        _form = EmulatorForm(plugin)
        Swing.runIfSwingOrRunLater(lambda: _form.setupUI(form))
    except Exception as e:
        logging.exception(e)

