"""
Utilities for working with encoded/encrypted strings.
"""
from __future__ import annotations
import logging
import re
import sys
from typing import Iterable, Tuple, Union

import dragodis

logger = logging.getLogger(__name__)

# fmt: off
# Codecs used to detect encoding of strings.
CODE_PAGES = [
    "ascii",
    "utf-32-be", "utf-32-le", "utf-16-be", "utf-16-le", "utf-8",  # General (utf-7 omitted)
    "gb18030", "gbk",  # Unified Chinese
    "gb2312", "hz",  # Simplified Chinese
    "big5hkscs", "big5",  # Traditional Chinese (cp950 omitted)
    "koi8-r", "iso8859-5", "cp1251", "mac-cyrillic",  # Cyrillic (cp866, cp855 omitted)
    "cp949",  # Korean (johab, iso2022-kr omitted)
    "iso8859-6", "cp1256",  # Arabic (cp864, cp720 omitted)
    "latin1",  # If all else fails, latin1 is always is successful.
]
# fmt: on

# CODEC to use for displaying strings in IDA, etc.
DISPLAY_CODE = "cp437" if sys.platform == "win32" else "ascii"


# TODO: Add support for forcing only utf-16 or utf-8 string data?
def find_string_data(data: bytes) -> Iterable[Tuple[int, bytes, str]]:
    """
    Iterates string data found within the given data.
    This looks for the start of UTF-8 or UTF-16 strings found within the given block of data.

    :param data: Chunk of data that contains a mixture of UTF-8 and UTF-16 encoded strings.
    :yields: (start_offset, string_data, encoding)
    """
    if not data or data in (b"\x00", b"\x00\x00"):
        return

    # Iterate strings split up by either \x00\x00 or \x00.
    # If we find a single character followed by a \x00, this is most likely a character of utf-16.
    offset = 0
    buffer = b""
    utf_16 = False
    for entry in re.split(b"((?<=\x00[^\x00]\x00)\x00\x00|\x00)", data):
        buffer += entry
        offset += len(entry)
        string_offset = offset - len(buffer)

        # If we have a single character, then this is most likely part of a utf-16 string.
        # Don't yield anything yet.
        if len(entry) == 1 and entry != b"\x00":
            utf_16 = True

        # If we find a single null character and not currently extracting a utf-16 string,
        # we found the end of a utf-8 string.
        elif entry == b"\x00" and not utf_16:
            if buffer not in (b"\x00", b"\x00\x00"):
                yield string_offset, buffer, "utf-8"
            buffer = b""

        # If we find a double null character, this is the end of a utf-16 string.
        elif entry == b"\x00\x00":
            if buffer not in (b"\x00", b"\x00\x00"):
                yield string_offset, buffer, "utf-16-le"
            buffer = b""
            utf_16 = False

        # If we find a multi-character string but in utf_16 mode, then we misidentified the utf-16.
        # Yield buffer as single character utf-8 strings and then reset buffer to entry.
        elif len(entry) > 1 and utf_16:
            split_strings = []
            for _entry in re.split(b"(\x00)", buffer[:-len(entry)]):
                if _entry == b"\x00":
                    split_strings[-1] += _entry
                else:
                    split_strings.append(_entry)
            for _entry in split_strings:
                if _entry:
                    yield string_offset, _entry, "utf-8"
                string_offset += len(_entry)
            buffer = buffer[-len(entry):]
            utf_16 = False

    # Yield remaining string that may not have a null terminator.
    if buffer and buffer not in (b"\x00", b"\x00\x00"):
        string_offset = offset - len(buffer)
        if utf_16:
            # If we have no ending null byte and there is a null byte in front, then it must be big endian.
            if not buffer.endswith(b"\x00") and len(buffer) < len(data) and data[string_offset-1] == 0x00:
                buffer = b"\x00" + buffer
                yield string_offset - 1, buffer, "utf-16-be"
            else:
                yield string_offset, buffer, "utf-16-le"
        else:
            yield string_offset, buffer, "utf-8"


def get_terminated_bytes(dis: dragodis.Disassembler, addr: int, unit_width: int = 1) -> bytes:
    """
    Extracts null terminated bytes from given address.

    NOTE: This is different from dis.get_string_bytes() since it has no requirement for the data
    range to be a valid string. It just purely gets bytes up to the first null terminator.

    :param dis: Dragodis disassembler
    :param addr: Starting address to pull bytes from.
    :param unit_width: Byte width of string character.
    :return: Null terminated bytes.
    """
    terminator_address = dis.find_bytes(b"\x00" * unit_width, start=addr)
    if terminator_address == -1:
        raise ValueError(f"Unable to locate null terminator for 0x{addr:0X}")
    return dis.get_bytes(addr, terminator_address - addr)


class DecodedString:
    """
    Holds information about a decoded/decrypted string.

    :param dec_data: Decrypted/decoded string data
    :param enc_data: Original encrypted/encoded string data
    :param encoding: Known encoding used to decoded data into a string
        If not provided, this will be detected using dec_data.
    :param enc_source: The address or dragodis variable object where the enc_data was found.
    :param dec_source: The address or dargodis variable object where the dec_data was found.
    """

    _MAX_COMMENT_LENGTH = 130
    _MAX_NAME_LENGTH = 30

    def __init__(
            self,
            dec_data: bytes,
            enc_data: bytes = None,
            encoding: str = None,
            enc_source: Union[None, int, dragodis.interface.Variable] = None,
            dec_source: Union[None, int, dragodis.interface.Variable] = None,
    ):
        self.data = dec_data
        self.enc_data = enc_data
        self.encoding = encoding or self.detect_encoding(dec_data)
        self.enc_source = enc_source
        self.dec_source = dec_source

    def __str__(self):
        """
        Detects and decodes string data.
        """
        return self.data.decode(self.encoding).rstrip("\x00")

    def __bytes__(self):
        return self.data

    def _num_raw_bytes(self, string: str) -> int:
        """
        Returns the number of raw bytes found in the given unicode string
        """
        count = 0
        for char in string:
            char = char.encode("unicode-escape")
            count += char.startswith(b"\\x") + char.startswith(b"\\u") * 2
        return count

    def detect_encoding(self, data: bytes) -> str:
        """
        Detects and decodes data using best guess encoding.

        :returns: Decoded string and encoding used.
        """
        best_score = len(data)  # lowest score is best
        best_code_page = None
        best_output = None
        for code_page in CODE_PAGES:
            try:
                output = data.decode(code_page).rstrip(u"\x00")
            except UnicodeDecodeError:
                # If it's UTF we may need to strip away some null characters before decoding.
                if code_page in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
                    data_copy = data
                    while data_copy and data_copy[-1] == 0:
                        try:
                            data_copy = data_copy[:-1]
                            output = data_copy.decode(code_page).rstrip(u"\x00")
                        except UnicodeDecodeError:
                            continue
                        break  # successfully decoded
                    else:
                        continue
                # otherwise the code page isn't correct.
                else:
                    continue

            score = self._num_raw_bytes(output)
            if not best_output or score < best_score:
                best_score = score
                best_output = output
                best_code_page = code_page

        if best_output:
            return best_code_page

        # We shouldn't hit here since "latin1" should at least hit, but just incase...
        return "unicode_escape"

    @property
    def display_name(self) -> str:
        """Returns a disassembler friendly, printable name for the decoded string."""
        return str(self).encode(DISPLAY_CODE, "replace").decode(DISPLAY_CODE)

    def _annotate(
            self,
            dis: dragodis.Disassembler,
            item: Union[int, dragodis.interface.Line, dragodis.interface.Variable],
            name: str = None, comment: str = None
    ):
        """
        Annotates a Dragodis object
        """
        if isinstance(item, int):
            item = dis.get_line(item)
        if name:
            item.name = name
        if comment:
            if isinstance(item, dragodis.interface.GlobalVariable):
                item = dis.get_line(item.address)
                item.set_comment(comment, dragodis.CommentType.repeatable)
            if isinstance(item, dragodis.interface.Line):
                item.set_comment(comment, dragodis.CommentType.repeatable)

    def rename(self, dis: dragodis.Disassembler, name=None):
        """
         Renames (and comments) the string variable in the disassembler.

         :param str name: New name to given encoded string. (defaults to the decoded string itself)
         """
        name = name or self.display_name
        name = name[:self._MAX_NAME_LENGTH]

        # Add comment
        comment = 'Dec: "{}"'.format(name[: self._MAX_COMMENT_LENGTH])
        if len(name) > self._MAX_COMMENT_LENGTH:
            comment += " (truncated)"
        # TODO: Determine what to do when a stack source
        if self.enc_source:
            self._annotate(dis, self.enc_source, name="enc_"+name, comment=comment)
        if self.dec_source:
            self._annotate(dis, self.dec_source, name=name)
            # TODO: Setting datatype on a Variable is not current supported.
            # self.dec_source.data_type = dragodis.DataType.name

    def patch(self, dis: dragodis.Disassembler, fill_char=b"\x00", rename=True):
        """
        Patches the decrypted string data into the underlying disassembler.

        :param dis: Dragodis disassembler
        :param fill_char:
            Character to use to fill left over space if decrypted data
            is shorter than its encrypted data.
            (Set to None to leave the original data)
        :param rename:
            Whether to also rename the variable names.
            (This can also be done manually by using .rename())
        """
        if rename:
            self.rename(dis)

        if self.dec_source:
            dec_data = self.data
            if fill_char:
                dec_data += fill_char * (len(self.enc_data) - len(dec_data))
            dec_source = self.dec_source
            if isinstance(dec_source, int):
                dec_source = dis.get_line(dec_source)
                dec_source.data = dec_data
            elif isinstance(dec_source, dragodis.interface.GlobalVariable):
                dec_source = dis.get_line(dec_source.address)
                dec_source.data = dec_data
            else:
                logger.warning(f"Unable to patch {dec_source!r}")
