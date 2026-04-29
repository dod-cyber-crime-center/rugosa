"""
Utility functions for extracting high-level objects or actions using emulation.
"""
import logging
from typing import Iterable

import dragodis
from rugosa.emulation.emulator import Emulator
from rugosa.emulation.actions import Action
from rugosa.emulation.objects import Object

logger = logging.getLogger(__name__)


def find_objects(dis: dragodis.Disassembler, start: int = None) -> Iterable[Object]:
    """
    Uses emulation to search for and evaluate objects.

    :param dis: Dragodis disassembler
    :param start: The address to start tracing objects.
        Defaults to tracing all functions in the sample.

    :yields: Object objects
    """
    emulator = Emulator(dis, branch_tracking=False)
    yield from emulator.find_objects(start=start)


def find_actions(dis: dragodis.Disassembler, start: int = None) -> Iterable[Action]:
    """
    Uses emulation to search for and evaluate objects.

    :param dis: Dragodis disassembler
    :param start: The address to start tracing actions.
        Defaults to tracing all functions in the sample.

    :yields: Object objects
    """
    emulator = Emulator(dis, branch_tracking=False)
    yield from emulator.find_actions(start=start)
