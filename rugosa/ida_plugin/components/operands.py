
from __future__ import annotations
from typing import TYPE_CHECKING

import ida_kernwin
import ida_bytes
from PyQt5 import QtWidgets

if TYPE_CHECKING:
    from rugosa.ida_plugin.components.emulator import EmulatorForm


class Operands:

    def __init__(self, ui: EmulatorForm):
        self._ctx = None
        self.ui = ui
        self.table = ui.operands_table
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.table.itemDoubleClicked.connect(ui.redirect)
        self.table.customContextMenuRequested.connect(self.context_menu)

    def context_menu(self, pos):
        if not self._ctx:
            return
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        operand = self._ctx.operands[self.table.rowAt(pos.y())]
        address = operand.addr or operand.value

        menu = QtWidgets.QMenu(self.table)
        jump = menu.addAction("Jump to disassembly")
        jump.setEnabled(ida_bytes.is_loaded(address))
        show_in_memory = menu.addAction("Show in Memory")
        show_in_memory.setEnabled(self._ctx.memory.is_mapped(address))

        action = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if action == jump:
            ida_kernwin.jumpto(address)
        elif action == show_in_memory:
            # Size of pointed to value is unknown, so just showing the first 256 bytes.
            self.ui.memory.show_with_data(address, 256)

    def populate(self, ctx):
        """
        Populates the operands table.
        """
        self._ctx = ctx
        table = self.table
        operands = ctx.operands
        table.setRowCount(len(operands))
        for index, operand in enumerate(operands):
            table.setItem(index, 0, QtWidgets.QTableWidgetItem(str(operand.idx)))
            table.setItem(index, 1, QtWidgets.QTableWidgetItem(str(operand.width)))
            table.setItem(index, 2, QtWidgets.QTableWidgetItem(operand.text))
            if operand.addr is not None:
                table.setItem(index, 3, QtWidgets.QTableWidgetItem(hex(operand.addr)))
            else:
                table.setItem(index, 3, QtWidgets.QTableWidgetItem())
            value = operand.value
            if isinstance(value, int):
                value = hex(value)
            table.setItem(index, 4, QtWidgets.QTableWidgetItem(str(value)))

            # If value is a pointer, show the first few bytes of the referenced data
            value = operand.value
            if self._ctx.memory.is_mapped(value):
                data = self._ctx.memory.read(value, 24)
                table.setItem(index, 5, QtWidgets.QTableWidgetItem(str(data) + "..."))
            else:
                table.setItem(index, 5, QtWidgets.QTableWidgetItem())
