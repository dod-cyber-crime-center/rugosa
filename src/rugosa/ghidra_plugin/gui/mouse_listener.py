
from __future__ import annotations
from typing import TYPE_CHECKING

from jpype import JImplements, JOverride

if TYPE_CHECKING:
    from java.awt.event import MouseEvent


@JImplements("java.awt.event.MouseListener")
class MouseListener:

    def __init__(self, clicked=None, pressed=None, released=None, entered=None, exited=None):
        self._clicked = clicked
        self._pressed = pressed
        self._released = released
        self._entered = entered
        self._exited = exited

    @JOverride
    def mouseClicked(self, event: MouseEvent):
        if self._clicked:
            self._clicked(event)

    @JOverride
    def mousePressed(self, event: MouseEvent):
        if self._pressed:
            self._pressed(event)

    @JOverride
    def mouseReleased(self, event: MouseEvent):
        if self._released:
            self._released(event)

    @JOverride
    def mouseEntered(self, event: MouseEvent):
        if self._entered:
            self._entered(event)

    @JOverride
    def mouseExited(self, event: MouseEvent):
        if self._exited:
            self._exited(event)
