from __future__ import annotations
from typing import TYPE_CHECKING

import jpype

RugosaActionListener = jpype.JClass("dc3.rugosa.plugin.RugosaActionListener")

from rugosa.ghidra_plugin.gui.error_msg import catch_errors
from rugosa.ghidra_plugin.gui.table import TableModel


if TYPE_CHECKING:
    from rugosa.ghidra_plugin.components.emulator import EmulatorForm


class CallHistory:

    HEADERS = ["Address", "Function Call"]

    def __init__(self, form: EmulatorForm):
        self._ctx = None
        self.ui = form.ui
        self.table = self.ui.callHistoryTable

    @catch_errors
    def populate(self, ctx):
        """
        Populates the variables table.
        """
        self._ctx = ctx
        rows = []
        for call_address, func_name, args in ctx.call_history:
            args = ", ".join((f"{name}={hex(value)}" if name else hex(value)) for name, value in args)
            func_call = f"{func_name}({args})"
            rows.append([hex(call_address), func_call])
        self.table.setModel(TableModel(self.HEADERS, rows))
