"""
Interface for memory management.
"""
from __future__ import annotations

import io
import os
from typing import TYPE_CHECKING, Tuple, List, Optional, Iterable, Union
import warnings

import collections
import logging
from copy import deepcopy

import dragodis

from . import utils
from .constants import *

if TYPE_CHECKING:
    from rugosa.emulation.cpu_context import ProcessorContext

logger = logging.getLogger(__name__)


class Stream(io.RawIOBase):
    """
    Creates a file-like stream of the emulated memory.
    """

    def __init__(self, memory: Memory, start: int):
        self._memory = memory
        self._start = start
        self._offset = 0
        # Figure out which block we are in and use the end of the block as end.
        for base_address, size in memory.blocks:
            if start in range(base_address, base_address + size):
                self._end = size
                break
        else:
            raise RuntimeError(f"Failed to determine end address for memory stream starting at 0x{start:08X}")

    def readable(self) -> bool:
        return True

    def writeable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size == -1:
            return self.readall()
        size = min(self._end - self._offset, size)
        if size <= 0:
            return b""
        address = self.tell_address()
        data = self._memory.read(address, size)
        self._offset += len(data)
        return data

    def readline(self, size: int = 1) -> bytes:
        address = self.tell_address()
        end = self._memory.find(b"\n", start=address)
        if end == -1:
            return b""
        return self.read(end - address)

    def readall(self) -> bytes:
        return self.read(self._end - self._offset)

    def write(self, data: bytes) -> int:
        address = self.tell_address()
        num_bytes = self._memory.write(address, data)
        self._offset += num_bytes
        return num_bytes

    def tell(self) -> int:
        return self._offset

    def tell_address(self) -> int:
        return self._start + self._offset

    def seek(self, offset: int, whence=os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            if offset < 0:
                raise ValueError(f"Offset must be positive.")
            self._offset = offset
        elif whence == os.SEEK_CUR:
            self._offset = max(0, self._offset + offset)
        elif whence == os.SEEK_END:
            self._offset = min(self._end, self._end + offset)
        return self._offset

    def seek_address(self, address: int) -> int:
        return self.seek(address - self._start)


class PageMap(collections.defaultdict):
    """
    Dictionary of page indexes to pages.

    Creates a new page when missing.
    New pages uses the bytes from the IDB if in a segment.
    Segment pages will be mapped, but data retrieval will be delayed until the page
    is requested. (Helps to avoid unnecessary processing of large unused data segments.)
    """

    PAGE_SIZE = 0x1000

    def __init__(self, dis: dragodis.Disassembler, map_segments=True, _cache=None):
        # Setting default_factory to None, because we have overwritten it in __missing__()
        super().__init__(None)

        # Cache of segment pages.
        # Used to prevent multiple calls to pull data from the disassembler.
        if _cache is None:
            _cache = {}
        self._segment_cache = _cache

        self._dis = dis
        if map_segments:
            self.map_segments()

    def __deepcopy__(self, memo):
        copy = PageMap(self._dis, map_segments=False, _cache=self._segment_cache)
        memo[id(self)] = copy
        copy.update({index: (page[:] if page is not None else None) for index, page in self.items()})
        return copy

    def __missing__(self, page_index):
        """
        Creates a new page when index first encountered.

        :return: page
        :rtype: bytearray
        """
        ret = self[page_index] = self._new_page(page_index)
        return ret

    def __getitem__(self, page_index):
        try:
            page = super().__getitem__(page_index)
        except KeyError:
            return self.__missing__(page_index)

        # If page is None, that means this was set for delayed retrieval.
        # Retrieve page now that it is being requested.
        if page is None:
            return self.__missing__(page_index)

        return page

    def _is_delayed(self, page_index):
        """Determines if page is set for delayed retrieval."""
        return page_index in self and super().__getitem__(page_index) is None

    def map_segments(self):
        """Sets segment pages for delayed retrieval"""
        for segment in self._dis.segments:
            if segment.initialized:
                for page_index in range(segment.start >> 12, ((segment.end - 1) >> 12) + 1):
                    self[page_index] = None

    def _new_page(self, page_index: int) -> bytearray:
        """
        Creates a new page based on index.

        :return: page
        """
        if page_index in self._segment_cache:
            return self._segment_cache[page_index][:]

        start = page_index * self.PAGE_SIZE

        # TODO: Keep segment memory windows open and read from them.
        # If page was set for delayed retrieval it is coming from segment data, so pull from disassembler.
        # Update this check if ever use delayed retrieval for non-segment data.
        if self._is_delayed(page_index):
            logger.debug("Reading segment data 0x%X -> 0x%X from disassembler", start, start + self.PAGE_SIZE)
            page = bytearray(self._dis.get_bytes(start, self.PAGE_SIZE, default=0))
            self._segment_cache[page_index] = page[:]  # cache page first
            return page

        # If range is not in a segment, provide a page of all zeros.
        return bytearray(self.PAGE_SIZE)

    def peek(self, page_index: int) -> bytearray:
        """
        Returns the page for the given page index.
        If page doesn't exist, it creates the page but doesn't set it in the map.

        .. warning:: If you are using this you shouldn't try to modify the page since its
            effects may not propagate to the map.
            (ie. this is a read-only copy)

        :param page_index: Index of page to look at.
        :return: page
        """
        if page_index in self and not self._is_delayed(page_index):
            return self[page_index]
        return self._new_page(page_index)


class Memory:
    """
    Class which implements the CPU memory controller backed by the segment data in the input file.

    This class provides a read() and write() function for CPU emulation.
    If a memory address has not been written to, null bytes will be returned.
    """

    PAGE_SIZE = PageMap.PAGE_SIZE

    # Slack space between heap allocations.
    HEAP_SLACK = 0x3000

    # maximum amount of memory allowed to read/write
    # (if we are reading/writing more than ~ 268 MB we have bigger problems.)
    MAX_MEM_READ = 0x10000000
    MAX_MEM_WRITE = 0x10000000

    def __init__(self, cpu_context: ProcessorContext, _cache=None):
        """Initializes Memory object."""
        self._cpu_context = cpu_context
        self._pages = PageMap(cpu_context.emulator.disassembler, _cache=cpu_context.emulator._memory_cache)
        # A map of base addresses to size for heap allocations.
        self._heap_base = cpu_context.emulator.disassembler.max_address
        self._heap_allocations = {}

    def __deepcopy__(self, memo):
        klass = self.__class__
        copy = klass.__new__(klass)
        memo[id(self)] = copy

        copy._cpu_context = deepcopy(self._cpu_context, memo)
        copy._pages = deepcopy(self._pages, memo)
        copy._heap_allocations = self._heap_allocations.copy()
        copy._heap_base = self._heap_base

        return copy

    def open(self, start: int = None) -> Stream:
        """
        Opens memory as a file-like stream.

        :param start: Starting address for the window of data. (defaults to the address of the first allocated block)
        """
        if start is None:
            blocks = self.blocks
            if not blocks:
                raise ValueError("No memory blocks have been allocated.")
            start, _ = blocks[0]
        return Stream(self, start)

    @property
    def blocks(self) -> List[Tuple[int, int]]:
        """
        Returns a list of tuples containing the base address and size for
        contiguous blocks of memory.
        """
        # Collect ranges of continuous memory.
        memory_ranges = []
        base_address = None
        size = 0
        for page_index in sorted(self._pages):
            # First page of block?
            if base_address is None:
                base_address = page_index << 12

            size += self.PAGE_SIZE

            # Found end of continuous block of memory?
            if page_index + 1 not in self._pages:
                memory_ranges.append((base_address, size))
                base_address = None
                size = 0

        # Store last block
        if base_address is not None:
            memory_ranges.append((base_address, size))

        return memory_ranges

    def __str__(self):
        """
        Print information about current memory map.
        """
        # Create text output.
        _just = 25 if self._cpu_context.bitness == 32 else 50
        _hex_fmt = "0x{:08X}" if self._cpu_context.bitness == 32 else "0x{:016X}"
        title = f"{'Base Address'.ljust(_just)}{'Address Range'.ljust(_just)}{'Size'}"
        memory_ranges = []
        for base_address, size in self.blocks:
            memory_ranges.append(
                "{}{}{}".format(
                    _hex_fmt.format(base_address).ljust(_just),
                    "{} - {}".format(_hex_fmt.format(base_address), _hex_fmt.format(base_address + size)).ljust(_just),
                    size,
                )
            )

        return "{}\n{}\n".format(title, "\n".join(memory_ranges))

    def is_mapped(self, address: int) -> bool:
        return address >> 12 in self._pages

    def alloc(self, size: int) -> int:
        """
        Allocates heap region with size number of bytes.

        :param size: Number of bytes to allocate.
        :return: starting address of allocated memory.
        """
        # Allocate from HEAP_BASE if this is our first allocation.
        if not self._heap_allocations:
            address = self._heap_base
        # Otherwise, use the largest base address not used.
        # TODO: We may want to reuse previously freed space in the future.
        else:
            max_base_address = max(self._heap_allocations)
            heap_size = self._heap_allocations[max_base_address]
            address = max_base_address + heap_size + self.HEAP_SLACK

        # NOTE: We are just going to record that the memory as been allocated
        # but not actually trigger any data from being written. (The calls to write() will do that)
        # This helps to prevent us from wasting (real) memory if someone allocates
        # a huge amount of memory but only uses a small amount.
        self._heap_allocations[address] = size
        logger.debug("Allocated %d bytes at 0x%08X", size, address)
        return address

    def realloc(self, address: int, size: int) -> int:
        """
        Reallocates heap region with size number of bytes.

        :param address: base address to reallocate.
        :param size: Number of bytes to allocate.
        :return: address of the reallocated memory block.
        :raises ValueError: If given address is not allocated.
        """
        # Passed in address should be the base address of a previously allocated memory region.
        if address not in self._heap_allocations:
            raise ValueError(f"0x{address:X} address is not allocated.")

        previous_size = self._heap_allocations[address]

        # See if we need to relocate the heap address.
        if size > previous_size:
            for base_address in sorted(self._heap_allocations):
                if address < base_address < address + size:
                    # We need to relocate the memory block.
                    new_address = self.alloc(size)

                    # Copy over data from previous allocation.
                    # Since relocation is very rare, we will accept the loss in cycles
                    # if we end up writing empty data.
                    self.write(new_address, self.read(address, previous_size))

                    # Don't free the old, because the user may want to search it.
                    logger.debug("Relocated 0x%08X -> 0x%08X", address, new_address)

                    # Record a memory copy since the pointer has changed.
                    self._cpu_context.memory_copies[self._cpu_context.ip].append((address, new_address, size))

                    return new_address

        # Otherwise we just need to adjust the size.
        if previous_size != size:
            logger.debug(
                "Reallocating heap size at 0x%08X from %d to %d bytes.",
                address, previous_size, size
            )
            self._heap_allocations[address] = size
        return address

    def read(self, address: int, size: int) -> bytes:
        """
        Reads data from given address.

        :param address: Address to read data from.
        :param size: Number of bytes to read.

        :return: byte string of read data.
        :raises ValueError: If address or size is negative.
        """
        if address < 0:
            raise ValueError(f"Address must be a positive integer. Got 0x{address:08X}")
        if size < 0:
            raise ValueError("Size must be a positive integer.")
        if size > self.MAX_MEM_READ:
            logger.error(
                "Attempted to read %d bytes from 0x%08X. "
                "Ignoring request and reading the first %d bytes instead.",
                size, address, self.MAX_MEM_READ
            )
            size = self.MAX_MEM_READ

        logger.debug("Reading %d bytes from 0x%08X", size, address)

        page_index = address >> 12
        page_offset = address & 0xFFF

        # Read data from pages.
        out = bytearray()
        while size:
            # We don't want to trigger a page creation on read().. only write().
            page = self._pages.peek(page_index)
            read_bytes = page[page_offset : page_offset + size]
            out += read_bytes
            size -= len(read_bytes)
            page_offset = 0
            page_index += 1
        out = bytes(out)

        # logger.debug("Read: %r", out[:100])  # Enable this when debugging.
        return out

    def write(self, address: int, data: bytes) -> int:
        """
        Writes data to given address.

        :param address: Address to write data to.
        :param data: data to write
        :returns: Number of bytes written.

        :raises ValueError: If given address is negative.
        :raises TypeError: If given data type is invalid.
        """
        if address < 0:
            raise ValueError(f"Address must be a positive integer. Got 0x{address:08X}")

        size = len(data)
        if size > self.MAX_MEM_WRITE:
            logger.error(
                "Attempted to write %d bytes from 0x%08X. "
                "Ignoring request and writing the first %d bytes instead.",
                size, address, self.MAX_MEM_WRITE
            )
            data = data[: self.MAX_MEM_WRITE]
        size = len(data)

        logger.debug("Writing %d bytes to 0x%08X", size, address)
        # logger.debug("Writing: %r", data[:100])   # Enable this when debugging.

        page_index = address >> 12
        page_offset = address & 0xFFF

        # Write data into pages.
        while data:
            page = self._pages[page_index]
            split_index = self.PAGE_SIZE - page_offset
            to_write = data[:split_index]
            try:
                page[page_offset : page_offset + len(to_write)] = to_write
            except TypeError:
                raise TypeError("to_write: {} {}".format(type(to_write), repr(to_write)))
            data = data[split_index:]
            page_offset = 0
            page_index += 1

        return size

    def read_data(self, addr: int, size: int = None, data_type=None) -> Union[bytes, int]:
        """
        Reads memory at the specified address, of the specified size and convert
        the resulting data into the specified type.

        :param addr: address to read data from
        :param size: size of data to read
        :param data_type: type of data to be extracted
            (default to BYTE_STRING is size provided or STRING if not)
        """
        if not data_type:
            data_type = STRING if size is None else BYTE_STRING
        if size is None:
            size = 0

        if data_type == STRING:
            null_offset = self.find(b"\0", start=addr)
            # It should always eventually find a null since unmapped pages
            # are all null. If we get -1 we have a bug.
            assert null_offset != -1, "Unable to find a null character!"
            return self.read(addr, null_offset - addr)

        elif data_type == WIDE_STRING:
            # Step by 2 bytes to find 2 nulls on an even alignment.
            # (This helps prevent the need to take endianness into account.)
            null_offset = addr
            while self.read(null_offset, 2) != b"\0\0":
                null_offset += 2

            return self.read(addr, null_offset - addr)

        elif data_type == BYTE_STRING:
            return self.read(addr, size)

        elif data_type == BYTE:
            return self.read_int(addr, 1)

        elif data_type == WORD:
            return self.read_int(addr, 2)

        elif data_type == DWORD:
            return self.read_int(addr, 4)

        elif data_type == QWORD:
            return self.read_int(addr, 8)

        raise ValueError("Invalid data_type: {!r}".format(data_type))

    def read_int(self, addr: int, width: int = 4) -> int:
        """
        Helper function for reading an integer from the specified address.

        :param addr: address to read data from
        :param width: byte width of data to read
        :return: Integer read from address
        """
        data = self.read(addr, width)
        return int.from_bytes(data, self._cpu_context.byteorder)

    def read_string_bytes(self, addr: int, wide=False) -> bytes:
        """
        Helper function for reading a null terminated string at the given address.

        :param addr: address to read data from
        :param wide: Determines if data to be read is a wide or non-wide string.
            If true, data_type is assumed to be a STRING.
            If false, data_type is assumed to be a WIDE_STRING.
        :return: Bytes containing a string.
        """
        return self.read_data(addr, data_type=WIDE_STRING if wide else STRING)

    def read_string(self, addr: int, wide=False, encoding=None) -> str:
        """
        Helper function for reading and decoding a null terminated string
        at the given address.

        :param addr: address to read data from
        :param wide: Determines if data to be read is a wide or non-wide string.
            If true, data_type is assumed to be a STRING.
            If false, data_type is assumed to be a WIDE_STRING.
        :param encoding: Encoding to use for decoding.
            (defaults to utf8 for non-wide strings, and utf-16-le for wide strings.)
        :return: Decoded string
        """
        if not encoding:
            encoding = "utf-16-le" if wide else "utf8"
        data = self.read_string_bytes(addr, wide=wide)
        return data.decode(encoding)

    def write_data(self, addr: int, value: Union[str, bytes, int], data_type=None):
        """
        Writes memory at the specified address after converting the value
        into data based on the specified data type.

        :param addr: address to write data to
        :param value: integer or byte string to write
        :param data_type: type of data to convert value from.
            (defaults to BYTE_STRING, STRING, or DWORD based on input data)
        """
        if not data_type:
            if isinstance(value, str):
                data_type = STRING
            elif isinstance(value, bytes):
                data_type = BYTE_STRING
            elif isinstance(value, int):
                data_type = DWORD
            else:
                raise ValueError(f"Invalid data type: {type(value)}")

        if data_type == BYTE_STRING:
            self.write(addr, value)
            return

        elif data_type == STRING:
            data = value
            if isinstance(data, str):
                data = data.encode("utf8")
            data += b"\0"
            self.write(addr, data)
            return

        elif data_type == WIDE_STRING:
            data = value
            if isinstance(data, str):
                data = data.encode("utf-16-le")
            data += b"\0\0"
            self.write(addr, data)
            return

        elif data_type == BYTE:
            self.write_int(addr, value, 1)
            return

        elif data_type == WORD:
            self.write_int(addr, value, 2)
            return

        elif data_type == DWORD:
            self.write_int(addr, value, 4)
            return

        elif data_type == QWORD:
            self.write_int(addr, value, 8)
            return

        raise ValueError(f"Invalid data_type: {repr(data_type)}")

    def write_int(self, addr: int, value: int, width: int = 4):
        """
        Helper function for writing an integer to the specified address.

        :param addr: address to write data to
        :param width: byte width of data
        """
        if width > 1:
            value = utils.unsigned(value, width * 8)
        data = value.to_bytes(width, self._cpu_context.byteorder)
        self.write(addr, data)

    def write_string(self, addr: int, value: Union[str, bytes], wide=False, encoding=None):
        """
        Helper function for encoding and writing a null terminated string
        at the given address.

        NOTE: This is basically the reverse of read_string()

        :param addr: address to write data to
        :param value: string to write
        :param wide: Determines if data to be written as a wide or non-wide string.
            If true, data_type is assumed to be a STRING.
            If false, data_type is assumed to be a WIDE_STRING.
        :param encoding: Encoding to use for encoding.
            (defaults to utf8 for non-wide strings, and utf-16-le for wide strings.)
        """
        if isinstance(value, str):
            if not encoding:
                encoding = "utf-16-le" if wide else "utf8"
            value = value.encode(encoding)
        self.write_data(addr, value, data_type=WIDE_STRING if wide else STRING)

    def copy(self, src: int, dst: int, size: int):
        """
        Copy data from src address to dst address.
        (Use this over read()/write() combo in order to allow the context to keep
        track of memory pointer history.)

        :param src: Source address
        :param dst: Destination address
        :param size: Number of bytes to copy over.
        """
        self._cpu_context.memory_copies[self._cpu_context.ip].append((src, dst, size))
        self.write(dst, self.read(src, size))

    def find(self, value: bytes, start: int = 0, end: Optional[int] = None) -> int:
        """
        Searches memory for given value.

        :param value: byte string to search for
        :param start: Starting address to start search (defaults to 0)
        :param end: Optional ending address to end search

        :return int: address where value was located or -1 if not found

        :raises ValueError: If search value is larger than a page.
        """
        # We are not going to handle things that could expand beyond multiple pages
        if len(value) >= self.PAGE_SIZE:
            raise ValueError(f"Search value must be less than {self.PAGE_SIZE} bytes, got {len(value)}")

        if end and end <= start:
            raise ValueError("Ending address must be greater than starting address.")

        page_index = start >> 12
        page_offset = start & 0xFFF

        if end:
            end_page_index = end >> 12
            end_page_offset = end & 0xFFF
        else:
            end_page_index = end_page_offset = None

        page = self._pages.peek(page_index)

        # First search for the entire value in the page.
        if end and end_page_index == page_index:
            # Since we end in this page, don't attempt to read overlap.
            offset = page.find(value, page_offset, end_page_offset)
            if offset <= -1:
                return -1
            return page_index << 12 | offset

        offset = page.find(value, page_offset)
        if offset > -1:
            return page_index << 12 | offset

        # If we can't find it, try again with part of the next page attached
        # to account for data overlapping onto another page.
        _start = max(page_offset, self.PAGE_SIZE - len(value) + 1)
        _end = self.PAGE_SIZE + len(value) - 1
        if end and end_page_index == page_index + 1:
            _end = min(_end, self.PAGE_SIZE + end_page_offset)
            if _end == self.PAGE_SIZE + end_page_offset and _end <= _start:
                return -1

        next_page = self._pages.peek(page_index + 1)
        offset = (page + next_page).find(value, _start, _end)
        if offset > -1:
            return page_index << 12 | offset
        else:
            # Jump to the next mapped page to continue the search.
            # return -1 if there are no more pages beyond.
            for _page_index in sorted(self._pages):
                if _page_index > page_index:
                    # Stop searching pages if we surpass the end.
                    if end and end <= _page_index << 12:
                        return -1
                    return self.find(value, start=_page_index << 12, end=end)
            return -1

    def finditer(self, value: bytes, start: int = 0, end: Optional[int] = None) -> Iterable[int]:
        """
        Searches for all instances of value within memory.
        """
        while True:
            offset = self.find(value, start=start, end=end)
            if offset == -1:
                return
            yield offset
            start = offset + len(value)

    def find_in_segment(self, value: bytes, addr_or_name: Union[int, str]) -> int:
        """
        Searches memory for given value within the range of a specific segment.

        :param bytes value: byte string to search for
        :param addr_or_name: segment name or address within segment.

        :return: address where value was located or -1 if not found
        """
        segment = self._cpu_context.emulator.disassembler.get_segment(addr_or_name)
        return self.find(value, start=segment.start, end=segment.end)

    def finditer_in_segment(self, value: bytes, addr_or_name: Union[int, str]) -> Iterable[int]:
        """
        Searches memory for given value within the range of a specific segment.

        :param bytes value: byte string to search for
        :param addr_or_name: segment name or address withing segment.

        :yields: address where value was located or -1 if not found
        """
        segment = self._cpu_context.emulator.disassembler.get_segment(addr_or_name)
        yield from self.finditer(value, start=segment.start, end=segment.end)

    def find_in_heap(self, value: bytes) -> int:
        """
        Searches memory for given value within the allocated heap.

        :param value: byte string to search for

        :return: address where value was located or -1 if not found
        """
        return self.find(value, start=self._heap_base)

    def finditer_in_heap(self, value: bytes) -> Iterable[int]:
        """
        Searches memory for given value within the allocated heap.

        :param value: byte string to search for

        :yields: address where value was located or -1 if not found
        """
        yield from self.finditer(value, start=self._heap_base)
