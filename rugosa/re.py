"""
Utility for running re within disassembled code.

This utility extends and overwrites the existing re API to work correctly within the
context of a disassembler.
This module works just like the builtin re module, but adjusts offsets to be virtual addresses
and allows for searching specific segments.

usage::
    import dragodis
    from rugosa import re


    ptn = re.compile('some pattern')

    with dragodis.open_program("input.exe") as dis:
        for match in ptn.finditer(dis, '.text'):
            print('found marker at 0x{:0x}'.format(match.start()))
"""

import re
from typing import Iterable, List, Optional

import dragodis
from dragodis.interface import Function


class Match(object):
    """
    Wraps the SRE_Match object returned by re.
    """

    def __init__(self, match, seg_start):
        self._match = match
        self._start = seg_start

    def __getattr__(self, item):
        """
        Redirects anything that this class doesn't support back to the matchobject class

        :param item:

        :return:
        """
        return getattr(self._match, item, None)

    def start(self, group=None):
        """
        Returns the match object start value with respect to the segment start.

        :param group: optional group to obtain the start of

        :return: virtual start address
        """
        if group:
            _group_start = self._match.start(group)
            if _group_start < 0:  # group exists, but not contributing to match
                return _group_start

            return _group_start + self._start

        return self._match.start() + self._start

    def end(self, group=None):
        """
        Returns the match object end value with respect to the segment start.

        :param group: optional group to obtain the end of

        :return: virtual end address
        """
        if group:
            _group_end = self._match.end(group)
            if _group_end < 0:  # group exists, but not contributing to match
                return _group_end

            return _group_end + self._start

        return self._match.end() + self._start


class Pattern(object):
    """
    Wraps the SRE_Pattern object returned by re.
    """

    def __init__(self, ptn, flags=0):
        if isinstance(ptn, (str, bytes)):
            self._re = re.compile(ptn, flags=flags)
        else:
            self._re = ptn

    @property
    def pattern(self):
        return self._re.pattern

    def search(self, dis: dragodis.Disassembler, segment_name: str = None) -> Optional[Match]:
        """
        Performs the search functionality on the entire file, searching each segment individually.

        :param dis: Dragodis disassembler.
        :param segment_name: Restrict searching to segment with provided name
        :return: match object modified to match the segment start address
        """
        segments = [dis.get_segment(segment_name)] if segment_name else dis.segments
        for segment in segments:
            match = self._re.search(segment.data)
            if match:
                return Match(match, segment.start)
        return None

    def finditer(self, dis: dragodis.Disassembler, segment_name=None) -> Iterable[Match]:
        """
        Performs the finditer functionality on the entire file, searching each segment individually.

        :param dis: Dragodis disassembler.
        :param segment_name: Restrict searching to segment with provided name

        :yield: match object
        """
        segments = [dis.get_segment(segment_name)] if segment_name else dis.segments
        for segment in segments:
            for match in self._re.finditer(segment.data):
                yield Match(match, segment.start)

    def findall(self, dis: dragodis.Disassembler, segment_name=None) -> List[Match]:
        """
        Performs the findall functionality on the entire file.

        :param dis: Dragodis disassembler.
        :param segment_name: Restrict searching to segment with provided name
        :return: list of match objects
        """
        segments = [dis.get_segment(segment_name)] if segment_name else dis.segments
        matches = []
        for segment in segments:
            matches.extend(self._re.findall(segment.data))
        return matches

    def find_functions(self, dis: dragodis.Disassembler, segment_name: str = None) -> Iterable[Function]:
        """
        Uses finditer() to search for functions that contains a match for the given
        regular expression pattern.

        :param dis: Dragodis disassembler.
        :param segment_name: Restrict searching to segment with provided name
        :yields: Function object for each function.
        """
        cache = set()
        for match in self.finditer(dis, segment_name):
            try:
                func = dis.get_function(match.start())
            except dragodis.NotExistError:
                continue

            if func not in cache:
                cache.add(func)
                yield func


def compile(pattern, flags=0):
    """Compile a regular expression returning a Pattern object."""
    return Pattern(pattern, flags=flags)


def search(pattern, dis: dragodis.Disassembler, segment_name: str = None, flags=0):
    """Search with regular expression, returning a Match object."""
    return Pattern(pattern, flags=flags).search(dis, segment_name=segment_name)


def finditer(pattern, dis: dragodis.Disassembler, segment_name: str = None, flags=0):
    """Iterator of non-overlapping matches."""
    ptn = Pattern(pattern, flags=flags)
    yield from ptn.finditer(dis, segment_name=segment_name)


def findall(pattern, dis: dragodis.Disassembler, segment_name: str = None, flags=0):
    """Returns a list of non-overlapping matches."""
    return Pattern(pattern, flags=flags).findall(dis, segment_name=segment_name)


def find_functions(pattern, dis: dragodis.Disassembler, segment_name: str = None, flags=0) -> Iterable[Function]:
    """
    Uses finditer() to search for functions that contains a match for the given
    regular expression pattern.

    Yields dragodis.interface.Function object for each function.
    """
    if isinstance(pattern, Pattern):
        _regex = pattern
    else:
        _regex = Pattern(pattern, flags)

    yield from pattern.find_functions(dis, segment_name=segment_name)
