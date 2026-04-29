from __future__ import annotations
from typing import TYPE_CHECKING, Optional, Tuple

import jpype
from hexdump import hexdump

RugosaActionListener = jpype.JClass("dc3.rugosa.plugin.RugosaActionListener")

from rugosa.ghidra_plugin.gui.error_msg import show_exception, catch_errors
from rugosa.ghidra_plugin.gui.table import TableModel
from rugosa.ghidra_plugin.gui.mouse_listener import MouseListener

if TYPE_CHECKING:
    from java.awt.event import ActionEvent, MouseEvent
    from rugosa.ghidra_plugin.components.emulator import EmulatorForm


class Memory:

    HEADERS = ["Start", "End", "Size"]

    def __init__(self, form: EmulatorForm):
        self._ctx = None
        self.form = form
        self.ui = form.ui
        self.start = self.ui.memoryStart
        self.size = self.ui.memorySize
        self.hexdump = self.ui.memoryHexDump
        self.blocks_table = self.ui.memoryBlocksTable

        self.blocks_table.addMouseListener(MouseListener(clicked=self.load_from_block))
        self.ui.memoryLoadButton.addActionListener(RugosaActionListener @ (lambda event: self.populate_hexdump()))
        self.ui.memoryExportButton.addActionListener(RugosaActionListener @ self.export)

    @catch_errors
    def show_with_data(self, address: int, size: int):
        """
        Displays given address in hexdump
        """
        self.start.setText(hex(address))
        self.size.setValue(size)
        self.populate_hexdump()
        self.ui.tabs.setSelectedComponent(self.ui.memoryTab)

    def _get_data(self) -> Optional[Tuple[int, bytes]]:
        """
        Obtain the start address and data currently requested in memory tab.
        """
        if not self._ctx:
            return

        start_address = self.start.getText()
        if not start_address:
            # Clear hexdump if address is empty (startup)
            self.hexdump.setText("")
            return

        # First validate start address
        try:
            start_address = int(self.start.getText(), 16)
        except ValueError as e:
            show_exception(e, "Invalid address")
            return

        size = self.size.getValue()

        try:
            data = self._ctx.memory.read(start_address, size)
            return start_address, data
        except Exception as e:
            show_exception(e, "Failed to read memory.")
            return

    @catch_errors
    def populate_hexdump(self):
        """
        Loads hexdump in memory tab.
        """
        ret = self._get_data()
        if not ret:
            return
        start_address, data = ret

        # Get hex dump
        lines = []
        for line in hexdump(data, result="generator"):
            # Replace address with one offset
            addr, _, rest = line.partition(":")
            addr = int(addr, 16) + start_address
            line = f"{addr:08X}: {rest}"
            lines.append(line)
        dump = "\n".join(lines)
        self.hexdump.setText(dump)
        self.hexdump.scrollToTop()

    @catch_errors
    def load_from_block(self, event: MouseEvent):
        if not self._ctx:
            return
        if event.getClickCount() == 2:  # double click
            base_address, size = self._ctx.memory.blocks[event.getSource().getSelectedRow()]
            self.start.setText(hex(base_address))
            self.size.setValue(size)
            self.populate_hexdump()

    @catch_errors
    def export(self, event: ActionEvent):
        """
        Exports current memory hexdump view to a file as raw binary.
        """
        if not self._ctx:
            return
        ret = self._get_data()
        if not ret:
            return
        start_address, data = ret

        from docking.widgets.filechooser import GhidraFileChooser
        chooser = GhidraFileChooser(self.ui.memoryTab)
        chooser.setMultiSelectionEnabled(False)
        chooser.setTitle("Dump Memory")
        file = chooser.getSelectedFile()
        if file:
            with open(file.getPath(), "wb") as outfile:
                outfile.write(data)

    @catch_errors
    def populate(self, ctx):
        """
        Populates the variables table.
        """
        self._ctx = ctx
        # Load the memory blocks table.
        rows = []
        for base_address, size in ctx.memory.blocks:
            rows.append([hex(base_address), hex(base_address + size), str(size)])
        self.blocks_table.setModel(TableModel(self.HEADERS, rows))

        # Load hexdump with any previously set fields.
        self.populate_hexdump()
