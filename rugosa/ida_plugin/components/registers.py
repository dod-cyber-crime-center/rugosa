from __future__ import annotations
from typing import TYPE_CHECKING

import ida_kernwin
import ida_bytes
from PyQt5 import QtWidgets

if TYPE_CHECKING:
    from rugosa.ida_plugin.components.emulator import EmulatorForm


class Registers:

    def __init__(self, ui: EmulatorForm):
        self._ctx = None
        self._register_names = None
        self.ui = ui
        self.table = ui.registers_table
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.table.itemDoubleClicked.connect(ui.redirect)
        self.table.customContextMenuRequested.connect(self.context_menu)

    def context_menu(self, pos):
        if not self._register_names:
            return
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        name = self._register_names[self.table.rowAt(pos.y())]
        value = self._ctx.registers[name]

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

    def populate(self, ctx):
        """
        Populates the registers table
        """
        self._ctx = ctx
        table = self.table
        self._register_names = [name for name in ctx.registers.names if ctx.registers[name] is not None]
        table.setRowCount(len(self._register_names))
        for index, name in enumerate(self._register_names):
            table.setItem(index, 0, QtWidgets.QTableWidgetItem(name))
            value = ctx.registers[name]
            table.setItem(index, 1, QtWidgets.QTableWidgetItem(hex(value)))

            # If value is a pointer, show the first few bytes of the referenced data
            if self._ctx.memory.is_mapped(value):
                data = self._ctx.memory.read(value, 24)
                table.setItem(index, 2, QtWidgets.QTableWidgetItem(str(data) + "..."))
            else:
                table.setItem(index, 2, QtWidgets.QTableWidgetItem(""))
