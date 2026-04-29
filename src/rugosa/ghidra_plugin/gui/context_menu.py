
from __future__ import annotations
from typing import TYPE_CHECKING, Tuple

from jpype import JImplements, JOverride

if TYPE_CHECKING:
    from docking.widgets.table import GTable
    from docking import ActionContext


@JImplements("dc3.rugosa.plugin.RugosaDockingAction")
class TableContextMenuEntry:
    NAME = ""

    def __init__(self, component: GTable):
        self._component = component

    def _get_coords(self) -> Tuple[int, int]:
        return self._component.getSelectedRow(), self._component.getSelectedColumn()

    def enabled(self, row: int, col: int) -> bool:
        return False

    @JOverride
    def isAddToPopup(self, context: ActionContext) -> bool:
        if context.getSourceComponent() != self._component:
            return False
        return self.enabled(*self._get_coords())

    def clicked(self, row: int, col: int):
        ...

    @JOverride
    def actionPerformed(self, context: ActionContext):
        return self.clicked(*self._get_coords())
