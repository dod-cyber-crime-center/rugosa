"""
Utility for running YARA within the context of a disassembly.

This utility extends and overwrites the existing YARA API to work correctly within a dragodis context.

usage::
    from rugosa import yara

    # Compile a yara rule in the same way as the original yara library.
    rule = yara.compile(source=rule_text)

    with dragodis.open_program("input.exe") as dis:
        matches = rule.match(dis)  # Run rule on entire disassembled code.

        # Can also be used to run on segments.
        matches = rule.match(dis, segment='.text')

        # We can also just look for matching strings.
        for offset, identifer in rule.match_strings(dis):
            # ...
        for offset, identifer in rule.match_strings(dis, segment='.text'):
            # ...
"""

import logging
from typing import Iterable, List, Tuple, Union

import dragodis
from dragodis.interface import Function
import yara
from yara import *


logger = logging.getLogger(__name__)

READ_LENGTH = 10485760  # 10 MB


class Match:
    """
    Patches yara.Match to provide convert string offsets to virtual addresses.

    NOTE: We can't inherit yara.Match because they don't expose that class.

    :param yara.Match match_object: Original match object created by YARA
    :param int offset: Optional offset to offset string offsets by
    :param bool input_offset: Whether string offsets will be the file offset
        and should be converted.
    """

    def __init__(self, match_object, dis: dragodis.Disassembler, offset=None, file_offset=False):
        self._match = match_object
        self._dis = dis
        self._offset = offset
        self._file_offset = file_offset
        self._strings = None

    def __getattr__(self, item):
        return getattr(self._match, item)

    def __str__(self):
        return str(self._match)

    def __repr__(self):
        return repr(self._match)

    @property
    def strings(self):
        # Before returning strings, fixup the offsets to be virtual addresses.
        if self._strings is None:
            self._strings = []
            for offset, identifier, data in self._match.strings:
                if self._offset is not None:
                    offset += self._offset
                if self._file_offset:
                    offset = self._dis.get_virtual_address(offset)
                addr = self._dis.get_line(offset).address
                self._strings.append((addr, identifier, data))
        return self._strings


class Rules:
    """
    Patches yara.Rules to use our patched Match object when match() is called.

    NOTE: We can't inherit yara.Rules because they don't expose that class.
    """

    def __init__(self, rules_object):
        self._rules = rules_object
        self._infos = None

    def __getattr__(self, item):
        return getattr(self._rules, item)

    def _extract_info(self):
        """
        Retrieve information about the rule by performing a kludgy dance with callbacks.
        YARA should allow an easier way to give this information!
        """
        if self._infos is None:
            # YARA doesn't provide any easy way to get rule info, so we are going to have
            # to fake a match to get the info dictionary.
            self._infos = []

            def _callback(info):
                self._infos.append(info)
                return yara.CALLBACK_CONTINUE

            self._rules.match(data=b"", callback=_callback, which_callbacks=yara.CALLBACK_NON_MATCHES)
        return self._infos

    @property
    def names(self) -> List[str]:
        """Returns names of all the rules contained within."""
        infos = self._extract_info()
        return [info["rule"] for info in infos]

    def match(
            self, dis: dragodis.Disassembler, *args,
            input_offset=False, offset: int = None, segment: Union[str, int] = None, **kwargs
    ) -> List[Match]:
        """
        Patched to use our patched Match() object and allow for automatically running
        on IDB input file.

        Besides the default yara parameters, this implementation also includes:
            :param dis: Dragodis disassembler.
            :param *args: Positional arguments to pass to underlying yara.match() call.
            :param input_offset: Whether to apply input file offset to string offsets.
            :param offset: Optional offset to offset string offsets by.
            :param segment: Name or EA of segment to match to.
            :param **kwargs: Keyword arguments to pass to underlying yara.match() call.
        """
        # Run on segment.
        if segment:
            segment = dis.get_segment(segment)
            kwargs["data"] = segment.data
            offset = offset or segment.start
        # Run on input file.
        elif not (args or kwargs):
            args = (str(dis.input_path),)
            input_offset = True

        return [
            Match(match, dis, offset=offset, file_offset=input_offset)
            for match in self._rules.match(*args, **kwargs)
        ]

    def match_strings(self, *args, **kwargs) -> List[Tuple[int, str]]:
        """
        Runs match() but then returns tuples containing matched strings instead of Match objects.

        (This replicates the original legacy _YARA_MATCHES output)

        :returns: Tuple containing: (offset, identifier)
        """
        matched_strings = []
        for match in self.match(*args, **kwargs):
            for offset, identifier, _ in match.strings:
                matched_strings.append((offset, identifier))
        return matched_strings

    def find_functions(self, dis: dragodis.Disassembler, *args, **kwargs) -> Iterable[Function]:
        """
        Iterates functions that match the given rule text.
        """
        cache = set()
        for match in self.match(dis, *args, **kwargs):
            for ea, _, _ in match.strings:
                try:
                    func = dis.get_function(ea)
                except dragodis.NotExistError:
                    continue

                if func not in cache:
                    cache.add(func)
                    yield func


def compile(*args, **kwargs) -> Rules:
    """Wraps compiled rule in our patched Rules object."""
    return Rules(yara.compile(*args, **kwargs))


def load(*args, **kwargs) -> Rules:
    """Wraps loaded rule in our patched Rules object."""
    return Rules(yara.load(*args, **kwargs))


# Convenience functions ==============


def match(dis: dragodis.Disassembler, rule_text: str, *args, **kwargs) -> List[Match]:
    """Returns list of Match objects"""
    rule = compile(source=rule_text)
    return rule.match(dis, *args, **kwargs)


def match_strings(dis: dragodis.Disassembler, rule_text: str, *args, **kwargs) -> List[Tuple[int, str]]:
    """Returns list of (offset, string identifier)"""
    rule = compile(source=rule_text)
    return rule.match_strings(dis, *args, **kwargs)


def find_functions(dis: dragodis.Disassembler, rule_text: str, *args, **kwargs) -> Iterable[Function]:
    """
    Iterates functions that match the given rule text.
    """
    rule = compile(source=rule_text)
    yield from rule.find_functions(dis, *args, **kwargs)

# ====================================
