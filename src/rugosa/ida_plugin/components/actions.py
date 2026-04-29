from __future__ import annotations
from typing import TYPE_CHECKING

from PyQt5 import QtWidgets

if TYPE_CHECKING:
    from rugosa.ida_plugin.components.emulator import EmulatorForm


class Actions:

    def __init__(self, ui: EmulatorForm):
        self._ctx = None
        self.ui = ui
        self.table = ui.actions_table

    def populate(self, ctx):
        """
        Populate the actions table with current context.
        """
        self._ctx = ctx
        actions = ctx.actions
        table = self.table
        table.clear()
        table.setColumnCount(4)
        for action in reversed(actions):
            item = QtWidgets.QTreeWidgetItem([hex(action.ip), action.__class__.__name__, "", ""])
            for name, value in action:
                if name != "ip":
                    item.addChild(QtWidgets.QTreeWidgetItem(["", "", name, str(value)]))
            table.addTopLevelItem(item)
