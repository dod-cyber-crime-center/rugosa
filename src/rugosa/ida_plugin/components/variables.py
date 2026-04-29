from __future__ import annotations
from typing import TYPE_CHECKING

import ida_kernwin
import ida_bytes
from PyQt5 import QtWidgets

if TYPE_CHECKING:
    from rugosa.ida_plugin.components.emulator import EmulatorForm


class Variables:

    MAX_VALUE_SIZE = 256

    def __init__(self, ui: EmulatorForm):
        self._ctx = None
        self._variables = None
        self.ui = ui
        self.table = ui.variables_table
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.table.itemDoubleClicked.connect(ui.redirect)
        self.table.customContextMenuRequested.connect(self.context_menu)

    def context_menu(self, pos):
        if not self._variables:
            return
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        var = self._variables[self.table.rowAt(pos.y())]

        menu = QtWidgets.QMenu(self.table)
        jump = menu.addAction("Jump to disassembly")
        jump.setEnabled(ida_bytes.is_loaded(var.addr))
        show_in_memory = menu.addAction("Show in Memory")
        show_in_memory.setEnabled(self._ctx.memory.is_mapped(var.addr))

        action = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if action == jump:
            ida_kernwin.jumpto(var.addr)
        elif action == show_in_memory:
            self.ui.memory.show_with_data(var.addr, var.size)

    def populate(self, ctx):
        """
        Populate variables table
        """
        self._ctx = ctx
        table = self.table
        # Ignore " r" variable. That is a proprietary IDA thing just to keep track of return variables.
        self._variables = [var for var in ctx.variables if var.name != " r"]
        table.setRowCount(len(self._variables))
        for index, var in enumerate(self._variables):
            table.setItem(index, 0, QtWidgets.QTableWidgetItem(hex(var.addr)))
            table.setItem(index, 1, QtWidgets.QTableWidgetItem("" if var.stack_offset is None else hex(var.stack_offset)))
            data_type = var.data_type
            if var.count > 1 and data_type != "func_ptr":
                data_type += f"[{var.count}]"
            table.setItem(index, 2, QtWidgets.QTableWidgetItem(data_type))
            table.setItem(index, 3, QtWidgets.QTableWidgetItem(str(var.size)))
            table.setItem(index, 4, QtWidgets.QTableWidgetItem(var.name))
            value = var.value
            if isinstance(value, (list, bytes)) and len(value) > self.MAX_VALUE_SIZE:
                value = str(value[:self.MAX_VALUE_SIZE]) + " (truncated)"
            else:
                value = str(value)
            table.setItem(index, 5, QtWidgets.QTableWidgetItem(value))