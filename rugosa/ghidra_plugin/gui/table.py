"""
Interface for creating a TableModel for java.
"""
from __future__ import annotations
from typing import List, TYPE_CHECKING

from jpype import JImplements, JOverride


if TYPE_CHECKING:
    from java.lang import Object
    from javax.swing.event import TableModelListener


@JImplements("javax.swing.table.TableModel")
class TableModel:

    def __init__(self, headers: List[str], data: List[List[str]]):
        self._headers = headers
        self._data = data

    @JOverride
    def getRowCount(self) -> int:
        return len(self._data)

    @JOverride
    def getColumnCount(self) -> int:
        return len(self._headers)

    @JOverride
    def getColumnName(self, col: int):
        return self._headers[col]

    @JOverride
    def getColumnClass(self, col: int):
        from java.lang import String
        return String

    @JOverride
    def isCellEditable(self, row: int, col: int) -> bool:
        return False

    @JOverride
    def getValueAt(self, row: int, col: int) -> Object:
        return self._data[row][col]

    @JOverride
    def setValueAt(self, value, row: int, col: int):
        self._data[row][col] = str(value)

    @JOverride
    def addTableModelListener(self, listener: TableModelListener):
        ...

    @JOverride
    def removeTableModelListener(self, listener: TableModelListener):
        ...
