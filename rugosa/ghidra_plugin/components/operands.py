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

    def __init__(self, operands: Operands):
        super().__init__(operands.table)
        self._operands = operands

    @property
    def address(self):
        operand = self._operands._ctx.operands[self._component.getSelectedRow()]
        return operand.addr or operand.value


class JumpToDisassembly(ContextMenuEntry):
    NAME = "Jump To Disassembly"

    def enabled(self, row: int, col: int) -> bool:
        ctx = self._operands._ctx
        address = self.address
        return bool(ctx and address)

    @catch_errors
    def clicked(self, row: int, col: int):
        self._operands.form.plugin.goTo(self._operands.form.dis._to_addr(self.address))


class ShowInMemory(ContextMenuEntry):
    NAME = "Show in Memory"

    @catch_errors
    def enabled(self, row: int, col: int) -> bool:
        ctx = self._operands._ctx
        address = self.address
        return bool(ctx and address and ctx.memory.is_mapped(address))

    @catch_errors
    def clicked(self, row: int, col: int):
        self._operands.form.memory.show_with_data(self.address, 256)


class Operands:

    HEADERS = ["Index", "Size", "Text", "Address", "Value", "Referenced Data"]

    def __init__(self, form: EmulatorForm):
        self._ctx = None
        self.form = form
        self.ui = form.ui
        self.table = self.ui.operandsTable
        self.form.add_context_menu_entry(JumpToDisassembly(self))
        self.form.add_context_menu_entry(ShowInMemory(self))

    @catch_errors
    def populate(self, ctx):
        """
        Populates the operands table.
        """
        self._ctx = ctx
        operands = ctx.operands

        rows = []
        for operand in operands:
            row = [""] * len(self.HEADERS)
            row[0] = str(operand.idx)
            row[1] = str(operand.width)
            row[2] = operand.text

            if operand.addr is not None:
                row[3] = hex(operand.addr)

            value = operand.value
            if isinstance(value, int):
                value = hex(value)
            row[4] = str(value)

            # If value is a pointer, show the first few bytes of the referenced data
            value = operand.value
            if self._ctx.memory.is_mapped(value):
                data = self._ctx.memory.read(value, 24)
                row[5] = str(data) + "..."

            rows.append(row)

        # TODO: Add table listeners
        self.table.setModel(TableModel(self.HEADERS, rows))
