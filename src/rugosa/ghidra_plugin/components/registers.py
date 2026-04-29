from __future__ import annotations
from typing import TYPE_CHECKING

import jpype

RugosaActionListener = jpype.JClass("dc3.rugosa.plugin.RugosaActionListener")

from rugosa.ghidra_plugin.gui.error_msg import catch_errors
from rugosa.ghidra_plugin.gui.table import TableModel
from rugosa.ghidra_plugin.gui.context_menu import TableContextMenuEntry


if TYPE_CHECKING:
    from rugosa.ghidra_plugin.components.emulator import EmulatorForm


class ContextMenuEntry(TableContextMenuEntry):

    def __init__(self, registers: Registers):
        super().__init__(registers.table)
        self._registers = registers

    @property
    def address(self):
        name = self._registers._register_names[self._component.getSelectedRow()]
        return self._registers._ctx.registers[name]


class JumpToDisassembly(ContextMenuEntry):
    NAME = "Jump To Disassembly"

    def enabled(self, row: int, col: int) -> bool:
        ctx = self._registers._ctx
        address = self.address
        return bool(ctx and address)

    @catch_errors
    def clicked(self, row: int, col: int):
        self._registers.form.plugin.goTo(self._registers.form.dis._to_addr(self.address))


class ShowInMemory(ContextMenuEntry):
    NAME = "Show in Memory"

    @catch_errors
    def enabled(self, row: int, col: int) -> bool:
        ctx = self._registers._ctx
        address = self.address
        return bool(ctx and address and ctx.memory.is_mapped(address))

    @catch_errors
    def clicked(self, row: int, col: int):
        self._registers.form.memory.show_with_data(self.address, 256)


class Registers:

    HEADERS = ["Name", "Value", "Referenced Data"]

    def __init__(self, form: EmulatorForm):
        self._ctx = None
        self.form = form
        self._register_names = None
        self.ui = form.ui
        self.table = self.ui.registersTable
        self.form.add_context_menu_entry(JumpToDisassembly(self))
        self.form.add_context_menu_entry(ShowInMemory(self))

    @catch_errors
    def populate(self, ctx):
        """
        Populates the registers table.
        """
        self._ctx = ctx
        self._register_names = [name for name in ctx.registers.names if ctx.registers[name] is not None]

        rows = []
        for name in self._register_names:
            row = [""] * len(self.HEADERS)
            row[0] = name
            value = ctx.registers[name]
            row[1] = hex(value)

            # If value is a pointer, show the first few bytes of the referenced data
            if self._ctx.memory.is_mapped(value):
                data = self._ctx.memory.read(value, 24)
                row[2] = str(data) + "..."

            rows.append(row)

        # TODO: Add table listeners
        self.table.setModel(TableModel(self.HEADERS, rows))
