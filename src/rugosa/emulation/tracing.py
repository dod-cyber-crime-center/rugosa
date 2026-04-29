
from __future__ import annotations

import logging
from typing import Unpack, Iterable, TYPE_CHECKING

from rugosa.emulation.exceptions import MaxExecutionHit
from rugosa.emulation.monitors import ObjectMonitor, ActionMonitor
from rugosa.emulation.objects import Object, File, RegKey, Service
from rugosa.emulation.actions import Action
from rugosa.emulation.utils import cached_generator
from rugosa.emulation.stack_strings import StackStringsMonitor

if TYPE_CHECKING:
    from rugosa import Emulator, DecodedString
    from rugosa.emulation.emulator import IterContextArgs

logger = logging.getLogger(__name__)


class TracingMixin:
    """
    Adds tracing utilities to the Emulator class.
    """

    def trace(
            self: Emulator,
            start: int = None,
            ignored_exceptions: tuple[Exception] = (MaxExecutionHit, TimeoutError),
            **config: Unpack[IterContextArgs]
    ) -> Iterable:
        """
        Executes emulator with monitors attached.
        Yields back after each function has been emulated.
        """
        if start is None:
            for func in self.disassembler.functions():
                if not func.is_library:
                    logger.debug(f"Tracing {func.name}")
                    yield from self.trace(func.start, ignored_exceptions=ignored_exceptions, **config)
            return

        logger.debug(f"Tracing at 0x{start:08X}")
        try:
            self.exhaust(start, **config)
        except ignored_exceptions as e:
            logger.warning(f"Did not complete emulation at 0x{start:08X}: {e}")
        yield

    @cached_generator
    def find_objects(self: Emulator, start: int = None, **config: Unpack[IterContextArgs]) -> Iterable[Object]:
        """
        Executes emulator with object monitor attached.
        Yields back discovered objects.

        :param start: The address to start tracing objects.
            Defaults to tracing all functions in the sample.
        :param config: Arguments that match the iter_context_at() function.
        """
        with self.monitor(ObjectMonitor(scope="block")) as objects:
            for _ in self._trace(start, **config):
                yield from objects.latest()

    def find_actions(self: Emulator, start: int = None, **config: Unpack[IterContextArgs]) -> Iterable[Action]:
        """
        Executes emulator with action monitor attached.
        Yields back discovered objects.

        :param start: The address to start tracing actions.
            Defaults to tracing all functions in the sample.
        :param config: Arguments that match the iter_context_at() function.
        """
        with self.monitor(ActionMonitor(scope="code_path")) as actions:
            for _ in self._trace(start, **config):
                yield from actions.latest()

    def find_files(self, start: int = None, **config: Unpack[IterContextArgs]) -> Iterable[File]:
        """Finds and yields File objects found during iterative emulation."""
        for object in self.find_objects(start, **config):
            if isinstance(object, File):
                yield object

    def find_reg_keys(self, start: int = None, **config: Unpack[IterContextArgs]) -> Iterable[RegKey]:
        """Finds and yields RegKey objects found during iterative emulation."""
        for object in self.find_objects(start, **config):
            if isinstance(object, RegKey):
                yield object

    def find_services(self, start: int = None, **config: Unpack[IterContextArgs]) -> Iterable[Service]:
        """Finds and yields Service objects found during iterative emulation."""
        for object in self.find_objects(start, **config):
            if isinstance(object, Service):
                yield object

    @cached_generator
    def find_stack_strings(
            self: Emulator, start: int = None, min_length: int = 3, **config: Unpack[IterContextArgs]
    ) -> Iterable[DecodedString]:
        """
        Uses emulation to search for and evaluate stack strings.

        :param start: The address to start tracing stack strings.
            Defaults to tracing all functions in the sample.
        :param min_length: Minimal number of bytes to count as a stack string.

        :yields: DecodedString objects
        """
        with self.monitor(StackStringsMonitor(min_length=min_length)) as stack_strings:
            for _ in self.trace(start, **config):
                yield from stack_strings
                stack_strings.clear()

    def clear_tracing_cache(self):
        self.find_stack_strings.clear_cache(self)
        self.find_objects.clear_cache(self)
