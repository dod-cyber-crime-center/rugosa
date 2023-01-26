from __future__ import annotations
import logging
from typing import TYPE_CHECKING

import jpype

import dragodis

RugosaChangeListener = jpype.JClass("dc3.rugosa.plugin.RugosaChangeListener")

from rugosa.ghidra_plugin.gui.error_msg import catch_errors
from rugosa.ghidra_plugin.gui.table import TableModel
from rugosa.ghidra_plugin.gui.context_menu import TableContextMenuEntry


if TYPE_CHECKING:
    from javax.swing.event import ChangeEvent
    from rugosa.ghidra_plugin.components.emulator import EmulatorForm


logger = logging.getLogger(__name__)


class ContextMenuEntry(TableContextMenuEntry):

    def __init__(self, function_arguments: FunctionArguments):
        super().__init__(function_arguments.table)
        self._function_arguments = function_arguments

    @property
    def address(self):
        arg = self._function_arguments._arguments[self._component.getSelectedRow()]
        return arg.value


class JumpToDisassembly(ContextMenuEntry):
    NAME = "Jump To Disassembly"

    def enabled(self, row: int, col: int) -> bool:
        ctx = self._function_arguments._ctx
        address = self.address
        return bool(ctx and address)

    @catch_errors
    def clicked(self, row: int, col: int):
        self._function_arguments.form.plugin.goTo(self._function_arguments.form.dis._to_addr(self.address))


class ShowInMemory(ContextMenuEntry):
    NAME = "Show in Memory"

    def enabled(self, row: int, col: int) -> bool:
        ctx = self._function_arguments._ctx
        address = self.address
        return bool(ctx and address and ctx.memory.is_mapped(address))

    @catch_errors
    def clicked(self, row: int, col: int):
        self._function_arguments.form.memory.show_with_data(self.address, 256)


class FunctionArguments:

    MAX_VALUE_SIZE = 256
    HEADERS = ["Ordinal", "Location", "Data Type", "Size", "Name", "Address", "Value", "Referenced Data"]

    def __init__(self, form: EmulatorForm):
        self._ctx = None
        self._arguments = None
        self.form = form
        self.ui = form.ui
        self.table = self.ui.functionArgumentsTable
        self.signature = self.ui.functionSignature
        self.num_args = self.ui.numArgs
        self.num_args.addChangeListener(RugosaChangeListener @ self.num_args_updated)
        self.form.add_context_menu_entry(JumpToDisassembly(self))
        self.form.add_context_menu_entry(ShowInMemory(self))

    @catch_errors
    def num_args_updated(self, event: ChangeEvent):
        if self._ctx:
            # Need to be in transaction because we edit the function parameters in the databaes.
            with self.form.transaction():
                self.populate(self._ctx, num_args=self.num_args.getValue())

    def _populate_table(self, arguments):
        """
        Populates the function arguments table with given arguments.
        """
        self._arguments = arguments
        rows = []
        for arg in arguments:
            row = [""] * len(self.HEADERS)
            row[0] = str(arg.ordinal)
            row[1] = str(arg.location)
            row[2] = arg.type
            row[3] = str(arg.width)
            row[4] = arg.name
            addr = arg.addr
            if addr is not None:
                row[5] = hex(addr)
            row[6] = hex(arg.value)

            # If argument value is a pointer, show the first few bytes of the referenced data
            if self._ctx.memory.is_mapped(arg.value):
                data = self._ctx.memory.read(arg.value, 24)
                row[7] = str(data) + "..."

            rows.append(row)
        self.table.setModel(TableModel(self.HEADERS, rows))

    def populate(self, ctx, num_args=None):
        self._ctx = ctx

        try:
            func_sig = ctx.get_function_signature(num_args=num_args)
            if not func_sig:
                raise dragodis.NotExistError("No Operand.")
            self.num_args.setValue(jpype.JInt(len(func_sig.arguments)))
            self.signature.setText(
                f"{hex(func_sig.address)}: {func_sig.declaration}"
            )
            self._populate_table(func_sig.arguments)

        except dragodis.NotExistError:
            self.signature.setText("Function call not detected")
            self.table.setModel(TableModel(self.HEADERS, []))  # this clears the table
            return

        except Exception as e:
            self.signature.setText(f"Error: {e}")
            self.table.setModel(TableModel(self.HEADERS, []))
            logger.exception(e)
            return


