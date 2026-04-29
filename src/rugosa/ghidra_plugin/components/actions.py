from __future__ import annotations
from typing import TYPE_CHECKING

import jpype

RugosaActionListener = jpype.JClass("dc3.rugosa.plugin.RugosaActionListener")

from rugosa.ghidra_plugin.gui.error_msg import catch_errors
from rugosa.ghidra_plugin.gui.table import TableModel
from rugosa.ghidra_plugin.gui.mouse_listener import MouseListener


if TYPE_CHECKING:
    from java.awt.event import MouseEvent
    from rugosa.ghidra_plugin.components.emulator import EmulatorForm


class Actions:

    SIDE_HEADERS = ["Order", "Address", "Action"]
    FIELD_HEADERS = ["Name", "Value"]

    def __init__(self, form: EmulatorForm):
        self._ctx = None
        self._actions = None
        self.form = form
        self.ui = form.ui
        self.fields_table = self.ui.actionsFieldsTable
        self.side_table = self.ui.actionsSideTable
        # TODO: Figure out how to make a selection listener instead.
        self.side_table.addMouseListener(MouseListener(clicked=self.side_table_clicked))

    @catch_errors
    def side_table_clicked(self, event: MouseEvent):
        if not self._ctx:
            return
        action = self._actions[self.side_table.getSelectedRow()]
        self.populate_fields_table(action)

    @catch_errors
    def populate_fields_table(self, action):
        rows = []
        for name, value in action:
            if name != "ip":
                rows.append([name, str(value)])
        self.fields_table.setModel(TableModel(self.FIELD_HEADERS, rows))

    @catch_errors
    def populate(self, ctx):
        """
        Populates the variables table.
        """
        self._ctx = ctx
        self._actions = list(reversed(ctx.actions))

        rows = []
        for index, action in enumerate(self._actions):
            rows.append([str(index), hex(action.ip), action.__class__.__name__])
        self.side_table.setModel(TableModel(self.SIDE_HEADERS, rows))
