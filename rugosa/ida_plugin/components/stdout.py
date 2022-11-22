from __future__ import annotations
from typing import TYPE_CHECKING

import ida_kernwin
from PyQt5 import QtWidgets

if TYPE_CHECKING:
    from rugosa.ida_plugin.components.emulator import EmulatorForm


class Stdout:

    def __init__(self, ui: EmulatorForm):
        self._ctx = None
        self.ui = ui
        self.textdump = ui.stdout_textdump
        self.export_button = ui.stdout_export_button
        self.export_button.clicked.connect(self.export)

    def export(self):
        """
        Exports current stdout dump to a text file.
        """
        if not self._ctx:
            return
        file_path = ida_kernwin.ask_file(True, "*.txt", "Dump Stdout")
        if file_path:
            with open(file_path, "w") as outfile:
                outfile.write(self._ctx.stdout)

    def populate(self, ctx):
        """
        Populate the stdout text box with current stdout in context.
        """
        self._ctx = ctx
        self.textdump.setText(f"<pre>{ctx.stdout}</pre>")
