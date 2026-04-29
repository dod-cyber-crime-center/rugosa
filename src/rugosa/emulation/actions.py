"""
Interface for interesting actions.
"""

from dataclasses import dataclass, fields
import logging
from typing import Union, List, Optional, Iterable, Any, Tuple
from .call_hooks.win_api import win_constants as wc

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Action:
    ip: int

    def __iter__(self) -> Iterable[Tuple[str, Any]]:
        for field in fields(self):
            yield field.name, getattr(self, field.name)


class ActionList:
    """
    Represents a reverse linked list of actions that have occurred up
    to a specific ProcessorContext.
    """

    def __init__(self, *actions: Action):
        self.tail: Optional[ActionNode] = None
        for action in actions:
            self.add(action)

    def __repr__(self):
        return f"ActionList({repr(self.tail) if self.tail else ''})"

    def __deepcopy__(self, memo):
        copy = ActionList()
        copy.tail = self.tail
        return copy

    def __iter__(self):
        if self.tail:
            yield from self.tail

    def __reversed__(self):
        if self.tail:
            yield from reversed(self.tail)

    def __getitem__(self, index: int):
        return list(self)[index]

    def __len__(self):
        return len(list(self))

    def __bool__(self):
        return bool(self.tail)

    def __contains__(self, item):
        return any(item == action for action in self)

    def add(self, action: Action):
        self.tail = ActionNode(action, prev=self.tail)


class ActionNode:
    """
    Represents a node of a reverse linked list of actions that have occurred up
    to a specific ProcessorContext.
    """

    def __init__(self, action: Action, prev: Optional["ActionNode"] = None):
        self.action = action
        self.prev = prev

    def __repr__(self):
        if self.prev:
            return f"{self.prev!r} -> {self.action}"
        else:
            return f"{self.action}"

    def __iter__(self):
        """
        Iterates actions from the least recent action that has occurred to
        the most recent action that has occurred.
        """
        if self.prev:
            yield from self.prev
        yield self.action

    def __reversed__(self):
        """
        Iterates actions from the most recent action that has occurred to
        the least recent action that has occurred.
        """
        yield self.action
        if self.prev:
            yield from reversed(self.prev)


@dataclass(frozen=True)
class CommandExecuted(Action):
    command: str
    visibility: wc.Visibility = None


@dataclass(frozen=True)
class DirectoryCreated(Action):
    path: str


@dataclass(frozen=True)
class FileCreated(Action):
    handle: int
    path: str
    mode: str


@dataclass(frozen=True)
class FileOpened(Action):
    handle: int
    path: str
    mode: str


@dataclass(frozen=True)
class FileTruncated(Action):
    handle: int
    path: str
    mode: str


@dataclass(frozen=True)
class FileDeleted(Action):
    handle: int
    path: str


@dataclass(frozen=True)
class FileMoved(Action):
    handle: int
    old_path: str
    new_path: str


@dataclass(frozen=True)
class FileClosed(Action):
    handle: int


@dataclass(frozen=True)
class FileWritten(Action):
    handle: int
    data: bytes


@dataclass(frozen=True)
class RegKeyOpened(Action):
    handle: int
    path: str
    root_key: str
    sub_key: str


@dataclass(frozen=True)
class RegKeyDeleted(Action):
    handle: int
    path: str


@dataclass(frozen=True)
class RegKeyValueDeleted(Action):
    handle: int
    path: str
    value_name: str


@dataclass(frozen=True)
class RegKeyValueSet(Action):
    handle: int
    path: str
    data_type: str
    data: Union[bytes, str, tuple[str], int, None]


@dataclass(frozen=True)
class ServiceCreated(Action):
    handle: int
    name: str
    access: wc.ServiceAccess
    service_type: wc.ServiceType
    start_type: wc.ServiceStart
    display_name: str
    binary_path: str


@dataclass(frozen=True)
class ServiceOpened(Action):
    handle: int
    name: str


@dataclass(frozen=True)
class ServiceDeleted(Action):
    handle: int


@dataclass(frozen=True)
class ServiceDescriptionChanged(Action):
    handle: int
    description: str


@dataclass(frozen=True)
class ShellOperation(Action):
    operation: str
    path: str
    parameters: str
    directory: str
    visibility: wc.Visibility = None
