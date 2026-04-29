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

    def __init__(self, variables: Variables):
        super().__init__(variables.table)
        self._variables = variables

    @property
    def variable(self):
        if self._variables._ctx:
            return self._variables._variables[self._component.getSelectedRow()]


class JumpToDisassembly(ContextMenuEntry):
    NAME = "Jump To Disassembly"

    def enabled(self, row: int, col: int) -> bool:
        return bool(self.variable)

    @catch_errors
    def clicked(self, row: int, col: int):
        self._variables.form.plugin.goTo(self._variables.form.dis._to_addr(self.variable.addr))


class ShowInMemory(ContextMenuEntry):
    NAME = "Show in Memory"

    @catch_errors
    def enabled(self, row: int, col: int) -> bool:
        var = self.variable
        return var and self._variables._ctx.memory.is_mapped(var.addr)

    @catch_errors
    def clicked(self, row: int, col: int):
        var = self.variable
        self._variables.form.memory.show_with_data(var.addr, var.size)


class Variables:

    MAX_VALUE_SIZE = 256
    HEADERS = ["Address", "Stack Offset", "Data Type", "Size", "Name", "Value"]

    def __init__(self, form: EmulatorForm):
        self._ctx = None
        self._variables = None
        self.form = form
        self.ui = form.ui
        self.table = self.ui.variablesTable
        self.form.add_context_menu_entry(JumpToDisassembly(self))
        self.form.add_context_menu_entry(ShowInMemory(self))

    @catch_errors
    def populate(self, ctx):
        """
        Populates the variables table.
        """
        self._ctx = ctx
        self._variables = list(ctx.variables)

        rows = []
        for var in self._variables:
            row = [""] * len(self.HEADERS)
            row[0] = hex(var.addr)
            if var.stack_offset is not None:
                row[1] = hex(var.stack_offset)

            data_type = var.data_type
            if var.count > 1 and data_type != "func_ptr":
                data_type += f"[{var.count}]"
            row[2] = data_type

            row[3] = str(var.size)
            row[4] = var.name

            value = var.value
            if isinstance(value, (list, bytes)) and len(value) > self.MAX_VALUE_SIZE:
                value = str(value[:self.MAX_VALUE_SIZE]) + " (truncated)"
            else:
                value = str(value)
            row[5] = value

            rows.append(row)

        self.table.setModel(TableModel(self.HEADERS, rows))
