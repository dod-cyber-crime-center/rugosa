from __future__ import annotations
from typing import TYPE_CHECKING

from PyQt5 import QtWidgets

if TYPE_CHECKING:
    from rugosa.ida_plugin.components.emulator import EmulatorForm


class CallHistory:

    def __init__(self, ui: EmulatorForm):
        self._ctx = None
        self.ui = ui
        self.table = ui.call_history_table
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.table.itemDoubleClicked.connect(ui.redirect)

    def populate(self, ctx):
        """
        Populate the call history table with current context.
        """
        self._ctx = ctx
        call_history = ctx.call_history
        table = self.table
        table.setRowCount(len(call_history))
        for index, (call_address, func_name, args) in enumerate(call_history):
            args = ", ".join((f"{name}={hex(value)}" if name else hex(value)) for name, value in args)
            func_call = f"{func_name}({args})"
            table.setItem(index, 0, QtWidgets.QTableWidgetItem(hex(call_address)))
            table.setItem(index, 1, QtWidgets.QTableWidgetItem(func_call))
