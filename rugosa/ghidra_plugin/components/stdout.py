from __future__ import annotations
from typing import TYPE_CHECKING

import jpype
from rugosa.ghidra_plugin.gui.error_msg import catch_errors

RugosaActionListener = jpype.JClass("dc3.rugosa.plugin.RugosaActionListener")

if TYPE_CHECKING:
    from java.awt.event import ActionEvent
    from rugosa.ghidra_plugin.components.emulator import EmulatorForm


class Stdout:

    MAX_VALUE_SIZE = 256
    HEADERS = ["Address", "Stack Offset", "Data Type", "Size", "Name", "Value"]

    def __init__(self, form: EmulatorForm):
        self._ctx = None
        self.form = form
        self.ui = form.ui
        self.textdump = self.ui.stdoutTextDump
        self.ui.stdoutExportButton.addActionListener(RugosaActionListener @ self.export)

    @catch_errors
    def export(self, event: ActionEvent):
        """
        Exports current stdout dump to a text file.
        """
        if self._ctx:
            from docking.widgets.filechooser import GhidraFileChooser
            chooser = GhidraFileChooser(self.ui.stdoutTab)
            chooser.setMultiSelectionEnabled(False)
            chooser.setTitle("Export Stdout")
            file = chooser.getSelectedFile()
            if file:
                with open(file.getPath(), "w") as outfile:
                    outfile.write(self._ctx.stdout)

    def populate(self, ctx):
        """
        Populates the variables table.
        """
        self._ctx = ctx
        self.textdump.setText(ctx.stdout)
        self.textdump.scrollToTop()
