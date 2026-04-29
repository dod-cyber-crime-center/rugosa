"""
Interfaces for higher level elements such as open files or registry keys.
"""
from __future__ import annotations
import hashlib
import ntpath
import logging
from copy import deepcopy
from typing import Iterable, Type, TypeVar, Optional, Any

from rugosa.emulation.actions import FileOpened, Action, FileCreated, FileTruncated, FileDeleted, FileMoved, \
    FileWritten, FileClosed, RegKeyOpened, RegKeyDeleted, RegKeyValueDeleted, RegKeyValueSet, ServiceCreated, \
    ServiceOpened, ServiceDeleted, ServiceDescriptionChanged

logger = logging.getLogger(__name__)
T = TypeVar("T")


class ObjectMap:
    """
    Interface for obtaining high-level representations of objects encountered during emulation.
    """

    # The bounds on handles that can be used for Objects
    MIN_HANDLE = 0x80
    MAX_HANDLE = 0xFFFFFFFF - 1

    def __init__(self, cpu_context):
        self._cpu_context = cpu_context
        self._next_handle = self.MIN_HANDLE

    def __repr__(self):
        objs = "\n\t".join([repr(obj) for obj in self])
        return f"<ObjectMap : \n\t{objs}\n>"

    def __deepcopy__(self, memo):
        """
        Custom implementation of deepcopy to improve efficiency.
        """
        copy = ObjectMap(deepcopy(self._cpu_context, memo))
        copy._next_handle = self._next_handle
        return copy

    def __getitem__(self, handle: int) -> "Object":
        """Gets an object by handle"""
        if handle not in self:
            raise KeyError(f"Object with handle: {hex(handle)} does not exist.")

        actions = [
            action
            for action in self._cpu_context.actions
            if getattr(action, "handle", None) == handle
        ]
        # Determine the type of object to yield by peeking at the first action.
        # Default to generic Object.
        if actions:
            for object_class in Object.__subclasses__():
                if isinstance(actions[0], object_class.action_types):
                    return object_class(handle, actions)

        # Default to generic Object
        return Object(handle, actions)

    def get(self, handle: int, default=None) -> "Object":
        """Gets an object by handle"""
        try:
            return self[handle]
        except KeyError:
            return default

    def __len__(self) -> int:
        return self._next_handle - self.MIN_HANDLE

    def __contains__(self, handle: int) -> bool:
        return self.MIN_HANDLE <= handle < self._next_handle

    def __bool__(self):
        return self._next_handle > self.MIN_HANDLE

    def __iter__(self) -> Iterable["Object"]:
        """
        Yields all known objects based on current set of actions in the cpu context.
        Iterates least recently used to most.
        """
        for handle in self.handles:
            yield self[handle]

    def __reversed__(self) -> Iterable["Object"]:
        """
        Yields all known objects based on current set of actions in cpu context.
        Iterates most recently used to least.
        """
        for handle in reversed(self.handles):
            yield self[handle]

    @property
    def handles(self) -> list[int]:
        """
        List of allocated handles.
        """
        return list(range(self.MIN_HANDLE, self._next_handle))

    def alloc(self) -> int:
        """
        Allocates and returns the next available handle address.
        """
        if self._next_handle > self.MAX_HANDLE:
            raise ValueError("Too many handles created.")
        handle = self._next_handle
        self._next_handle += 1
        return handle

    def get_or_alloc(self, obj_type: Type["Object"], **query) -> int:
        """
        Returns the handle of a known object or a new handle if an object
        of type `obj_type` containing the attribute(s) equivalent to those
        found in `query` does not exist.
        """
        # First grab the most recent object containing the handle.
        # Reverse to ensure we get the most recent one.
        for obj in self.query(obj_type, reverse=True, **query):
            return obj.handle
        return self.alloc()

    def query(self, obj_type: Type[T], reverse=False, **conditions) -> Iterable[T]:
        """
        Returns the object based on given condition query.

        :param obj_type: Type of object to query for.
        :param reverse: Whether to produce objects from most recently used to least.
        :param conditions: Attributes to look for.
        :return:
        """
        for obj in (reversed(self) if reverse else self):
            if isinstance(obj, obj_type) \
                    and all(getattr(obj, attr_name) == value for attr_name, value in conditions.items()):
                yield obj

    def at(self, ip: int) -> list["Object"]:
        """
        Retrieves the objects referenced at the given instruction address.

        :param ip: Instruction address to get pointers from.
        :return: List of Object objects that were found within the given instruction.

        :raises ValueError: If instruction has not been executed yet.
        """
        if ip not in self._cpu_context.executed_instructions:
            raise ValueError(
                f"Unable to get objects. Instruction at 0x{ip:0x} has not been executed."
            )
        return [obj for obj in self if ip in obj.references]


class Object:
    """
    Represents a high level instantiated object during emulation.
    """

    # The type of Actions that builds the object.
    action_types = tuple()

    # noinspection PyDefaultArgument
    def __init_subclass__(cls, seen=set(), **kwargs):
        """Validates action types are unique per class."""
        if dups := set(cls.action_types).intersection(seen):
            raise RuntimeError(f"Found already claimed action types in {cls.__name__}: {dups}")
        seen.update(cls.action_types)

    def __bool__(self):
        return bool(self.actions)

    def __eq__(self, other):
        return self.handle == other.handle and self.actions == other.actions

    def __hash__(self):
        return hash((self.handle, *self.actions))

    def content_hash(self) -> int:
        """
        Returns a hash for the contents of the object.
        This hash ignores reference locations.
        """
        return hash(self.handle)

    def __init__(self, handle: int, actions: list[Action]):
        # The list of actions that are relevant to this object.
        self.handle = handle
        self.actions = actions

    def as_dict(self) -> dict[str, Any]:
        """
        Provides a serializable representation of the object.
        """
        return {
            "type": self.__class__.__name__,
            "handle": self.handle,
            "references": self.references,
        }

    @property
    def references(self) -> list[int]:
        """The address locations where this object has been encountered."""
        return [action.ip for action in self.actions]


class File(Object):
    """
    Stores information for opened files for a specific CPU context state.
    """

    action_types = (
        FileCreated, FileOpened, FileTruncated, FileDeleted, FileMoved, FileWritten, FileClosed
    )
    file_creation_types = (FileCreated, FileOpened, FileTruncated)

    def __repr__(self):
        data = self.data
        data_str = repr(data[:10])
        if len(data) > 10:
            data_str = data_str[:-1] + "..." + data_str[-1]
        # TODO: Update
        return (
            f"<File 0x{self.handle:08X}"
            f" : path = {self.path}"
            f" : mode = {self.mode}"
            f" : size = {len(data)}"
            f" : data = {data_str},"
            f" : closed = {self.closed},"
            f" : deleted = {self.deleted}"
            f">"
        )

    def __bool__(self):
        return bool(self.path or self.mode or self.data)

    def as_dict(self) -> dict[str, Any]:
        return {
            **super().as_dict(),
            "path": self.path,
            "mode": self.mode,
            "closed": self.closed,
            "deleted": self.deleted,
            "md5": self.md5,
            "data": self.data,
        }

    def content_hash(self) -> int:
        return hash((self.handle, self.path, self.mode, self.md5))

    @property
    def data(self) -> bytes:
        """The data written to the file."""
        return b"".join([action.data for action in self.actions if isinstance(action, FileWritten)])

    @property
    def md5(self) -> str:
        """The MD5 hash of the file."""
        return hashlib.md5(self.data).hexdigest()

    @property
    def path(self) -> Optional[str]:
        """The path of the file."""
        for action in reversed(self.actions):
            if isinstance(action, self.file_creation_types + (FileDeleted,)):
                return action.path
            elif isinstance(action, FileMoved):
                return action.new_path

    @property
    def name(self) -> Optional[str]:
        """The base name of the file."""
        if self.path:
            return ntpath.basename(self.path)

    @property
    def history(self) -> list[str]:
        """List of previous file paths."""
        history = []
        for action in self.actions:
            if isinstance(action, FileMoved):
                history.append(action.old_path)
        return history

    @property
    def mode(self) -> Optional[str]:
        """The mode the file was last opened with."""
        for action in reversed(self.actions):
            if isinstance(action, self.file_creation_types):
                return action.mode

    @property
    def closed(self) -> Optional[bool]:
        """
        Whether the file has been closed.
        If None, this information is unknown.
        """
        for action in reversed(self.actions):
            if isinstance(action, FileClosed):
                return True
            elif isinstance(action, self.file_creation_types):
                return False

    @property
    def deleted(self) -> Optional[bool]:
        """
        Whether the file has been deleted.
        If None, this information is unknown.
        """
        for action in reversed(self.actions):
            if isinstance(action, FileDeleted):
                return True
            elif isinstance(action, self.file_creation_types):
                return False


class RegKey(Object):
    """
    Stores information for opened registry keys for a specific CPU context state.
    """

    action_types = (
        RegKeyOpened, RegKeyDeleted, RegKeyValueDeleted, RegKeyValueSet
    )

    def __repr__(self):
        return (
            f"<RegKey 0x{self.handle:08X}"
            f" : root_key = {self.root_key}"
            f" : sub_key = {self.sub_key}"
            f" : values = {self.values}"
            f" : deleted = {self.deleted}"
            f" : value_deleted = {self.value_deleted}"
            f">"
        )

    def __bool__(self):
        return bool(self.root_key or self.sub_key)

    def as_dict(self) -> dict[str, Any]:
        return {
            **super().as_dict(),
            "root_key": self.root_key,
            "sub_key": self.sub_key,
            "values": self.values,
        }

    def content_hash(self) -> int:
        return hash((self.handle, self.root_key, self.sub_key, tuple(self.values)))

    @property
    def root_key(self) -> Optional[str]:
        """The root key of the registry key."""
        for action in reversed(self.actions):
            if isinstance(action, RegKeyOpened):
                return action.root_key

    @property
    def sub_key(self) -> Optional[str]:
        """The sub key of the registry key."""
        for action in reversed(self.actions):
            if isinstance(action, RegKeyOpened):
                return action.sub_key

    @property
    def path(self) -> Optional[str]:
        """The full path of the registry key."""
        if self.root_key and self.sub_key:
            return "\\".join([self.root_key, self.sub_key])

    @property
    def values(self) -> list[bytes | str| tuple[str] | int]:
        """
        The values that have been observed to be set within the registry key.
        """
        return [action.data for action in self.actions if isinstance(action, RegKeyValueSet)]

    @property
    def value(self) -> Optional[bytes | str | tuple[str] | int]:
        """
        The most recent value set within the registry key (if known).
        """
        for action in reversed(self.actions):
            if isinstance(action, RegKeyValueSet):
                return action.data

    @property
    def deleted(self) -> Optional[bool]:
        """
        Whether the registry key has been deleted.
        If None, this information is unknown.
        """
        for action in reversed(self.actions):
            if isinstance(action, RegKeyDeleted):
                return True
            elif isinstance(action, RegKeyOpened):
                return False

    @property
    def value_deleted(self) -> Optional[bool]:
        """
        Whether the registry key's value has been deleted.
        If None, this information is unknown.
        """
        for action in reversed(self.actions):
            if isinstance(action, RegKeyValueDeleted):
                return True
            elif isinstance(action, RegKeyValueSet):
                return False


class Service(Object):
    """
    Stores information pertaining to a service
    """

    action_types = (
        ServiceCreated, ServiceOpened, ServiceDeleted, ServiceDescriptionChanged
    )

    def __repr__(self):
        return (
            f"<Service 0x{self.handle:08X}"
            f" : name = {self.name}"
            f" : display_name = {self.display_name}"
            f" : binary_path = {self.binary_path}"
            f" : description = {self.description}"
            f">"
        )

    def __bool__(self):
        return bool(self.name or self.display_name or self.binary_path or self.description)

    def as_dict(self) -> dict[str, Any]:
        return {
            **super().as_dict(),
            "name": self.name,
            "display_name": self.display_name,
            "binary_path": self.binary_path,
            "description": self.description,
        }

    def content_hash(self) -> int:
        return hash((self.handle, self.name, self.display_name, self.binary_path, self.description))

    @property
    def name(self) -> Optional[str]:
        """The name of the service."""
        for action in reversed(self.actions):
            if isinstance(action, ServiceCreated) or isinstance(action, ServiceOpened):
                return action.name

    @property
    def display_name(self) -> Optional[str]:
        """The display name of the service"""
        for action in reversed(self.actions):
            if isinstance(action, ServiceCreated):
                return action.display_name

    @property
    def binary_path(self) -> Optional[str]:
        """The binary path of the service."""
        for action in reversed(self.actions):
            if isinstance(action, ServiceCreated):
                return action.binary_path

    @property
    def description(self) -> Optional[str]:
        """The description of the service"""
        for action in reversed(self.actions):
            if isinstance(action, ServiceDescriptionChanged):
                return action.description
