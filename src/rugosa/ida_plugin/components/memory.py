from __future__ import annotations
from typing import TYPE_CHECKING, Optional, Tuple

import ida_kernwin
from hexdump import hexdump
from PyQt5 import QtWidgets

if TYPE_CHECKING:
    from rugosa.ida_plugin.components.emulator import EmulatorForm


class Memory:

    def __init__(self, ui: EmulatorForm):
        self._ctx = None
        self.ui = ui
        self.start = ui.memory_start
        self.size = ui.memory_size
        self.hexdump = ui.memory_hexdump
        self.blocks_table = ui.memory_blocks_table
        self.blocks_table.itemDoubleClicked.connect(self.load_from_block)
        self.load_button = ui.memory_load_button
        self.load_button.clicked.connect(self.populate_hexdump)
        self.export_button = ui.memory_export_button
        self.export_button.clicked.connect(self.export)

    def show_with_data(self, address: int, size: int):
        """
        Displays given address in hexdump
        """
        self.start.setText(hex(address))
        self.size.setValue(size)
        self.populate_hexdump()
        self.ui.tabs.setCurrentWidget(self.ui.memory_tab)

    def _get_data(self) -> Optional[Tuple[int, bytes]]:
        """
        Obtain the start address and data currently requested in memory tab.
        """
        if not self._ctx:
            return

        start_address = self.start.text()
        if not start_address:
            # Clear hexdump if address is empty (startup)
            self.hexdump.setText("")
            return

        # First validate start address
        try:
            start_address = int(self.start.text(), 16)
        except ValueError as e:
            self.ui.show_exception(e, "Invalid address")
            return

        size = self.size.value()

        try:
            data = self._ctx.memory.read(start_address, size)
            return start_address, data
        except Exception as e:
            self.ui.show_exception(e, "Failed to read memory.")
            return

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
        self.hexdump.setText(f"<pre>{dump}</pre>")

    def load_from_block(self, item: QtWidgets.QTableWidgetItem):
        if not self._ctx:
            return
        base_address, size = self._ctx.memory.blocks[item.row()]
        self.start.setText(hex(base_address))
        self.size.setValue(size)
        self.populate_hexdump()

    def export(self):
        """
        Exports current memory hexdump view to a file as raw binary.
        """
        if not self._ctx:
            return
        ret = self._get_data()
        if not ret:
            return
        start_address, data = ret

        file_path = ida_kernwin.ask_file(True, "*.bin", "Dump Memory")
        if file_path:
            with open(file_path, "wb") as outfile:
                outfile.write(data)

    def populate(self, ctx):
        """
        On initial load, show the memory map in the hex view.
        """
        self._ctx = ctx
        # Load the memory blocks table.
        blocks = ctx.memory.blocks
        table = self.blocks_table
        table.setRowCount(len(blocks))
        for index, (base_address, size) in enumerate(blocks):
            table.setItem(index, 0, QtWidgets.QTableWidgetItem(hex(base_address)))
            table.setItem(index, 1, QtWidgets.QTableWidgetItem(hex(base_address + size)))
            table.setItem(index, 2, QtWidgets.QTableWidgetItem(str(size)))

        # Load hexdump with any previously set fields.
        self.populate_hexdump()
