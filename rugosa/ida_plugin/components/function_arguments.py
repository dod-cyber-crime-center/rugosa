from __future__ import annotations
from typing import TYPE_CHECKING

import ida_kernwin
import ida_bytes
import dragodis
from PyQt5 import QtWidgets

if TYPE_CHECKING:
    from rugosa.ida_plugin.components.emulator import EmulatorForm


class FunctionArguments:

    def __init__(self, ui: EmulatorForm):
        self._ctx = None
        self._arguments = None
        self.ui = ui
        self.table = ui.function_arguments_table
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.table.itemDoubleClicked.connect(ui.redirect)
        self.table.customContextMenuRequested.connect(self.context_menu)
        self.signature = ui.function_signature
        self.num_args = ui.num_args
        self.num_args.valueChanged.connect(self.num_args_updated)

    def context_menu(self, pos):
        if not self._arguments:
            return
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        arg = self._arguments[self.table.rowAt(pos.y())]
        value = arg.value

        menu = QtWidgets.QMenu(self.table)
        jump = menu.addAction("Jump to disassembly")
        jump.setEnabled(ida_bytes.is_loaded(value))
        show_in_memory = menu.addAction("Show in Memory")
        show_in_memory.setEnabled(self._ctx.memory.is_mapped(value))

        action = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if action == jump:
            ida_kernwin.jumpto(value)
        elif action == show_in_memory:
            # Size of pointed to value is unknown, so just showing the first 256 bytes.
            self.ui.memory.show_with_data(value, 256)

    def num_args_updated(self, value: int):
        if self._ctx:
            self.populate(self._ctx, num_args=value)

    def _populate_table(self, arguments):
        """
        Populates the function arguments table with given arguments
        """
        self._arguments = arguments
        table = self.table
        table.setRowCount(len(arguments))
        for index, arg in enumerate(arguments):
            table.setItem(index, 0, QtWidgets.QTableWidgetItem(str(arg.ordinal)))
            table.setItem(index, 1, QtWidgets.QTableWidgetItem(str(arg._parameter.location)))
            table.setItem(index, 2, QtWidgets.QTableWidgetItem(arg.type))
            table.setItem(index, 3, QtWidgets.QTableWidgetItem(str(arg.width)))
            table.setItem(index, 4, QtWidgets.QTableWidgetItem(arg.name))
            addr = arg.addr
            table.setItem(index, 5, QtWidgets.QTableWidgetItem(hex(addr) if addr is not None else ""))
            table.setItem(index, 6, QtWidgets.QTableWidgetItem(hex(arg.value)))

            # If argument value is a pointer, show the first few bytes of the referenced data
            if self._ctx.memory.is_mapped(arg.value):
                data = self._ctx.memory.read(arg.value, 24)
                table.setItem(index, 7, QtWidgets.QTableWidgetItem(str(data) + "..."))
            else:
                table.setItem(index, 7, QtWidgets.QTableWidgetItem(""))

    def populate(self, ctx, num_args=None):
        self._ctx = ctx
        try:
            func_sig = ctx.get_function_signature(num_args=num_args)
            if not func_sig:
                raise dragodis.NotExistError("No Operand.")
        except dragodis.NotExistError:
            self.signature.setText("Function call not detected.")
            self.table.setRowCount(0)  # TODO: This clears the column information.
            return
        except Exception as e:
            self.signature.setText(f"<font color=red>{e}</font>")
            self.table.setRowCount(0)
            return

        self.num_args.setValue(len(func_sig.arguments))
        self.signature.setText(
            f"{hex(func_sig.address)}: {func_sig.declaration}"
        )
        self._populate_table(func_sig.arguments)
