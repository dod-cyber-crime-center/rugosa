"""
Utilities for working with encoded/encrypted strings.
"""
from __future__ import annotations
import logging
import re
from string import printable as printable_chars
import sys
from typing import Iterable, Tuple, Union

import dragodis
from rugosa.emulation import Emulator


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
    "latin1",  # If all else fails, latin1 is always successful.
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


_api_names = [
    ("GetModuleHandleA", 0),
    ("GetModuleHandleW", 0),
    ("LoadLibraryA", 0),
    ("LoadLibraryW", 0),
    ("GetProcAddress", 1),
]


def find_api_resolve_strings(dis: dragodis.Disassembler) -> Iterable[Tuple[int, str]]:
    """
    Finds strings used in API resolution functions (e.g. GetProcAddress)

    :param dis: Dragodis disassembler

    :yields: (address, string) for API string.
    """
    seen = set()
    emulator = Emulator(dis)
    for api_name, arg_index in _api_names:
        try:
            imp = dis.get_import(api_name)
        except dragodis.NotExistError:
            continue
        for address in imp.calls_to:
            try:
                ctx = emulator.context_at(address)
                args = ctx.function_args
            except dragodis.NotExistError as e:
                logger.warning(f"Failed to emulate at 0x{address:08x}: {e}")
                continue

            if len(args) <= arg_index:
                continue

            ptr = args[arg_index].value
            if ptr in seen:
                continue

            # Only include strings actually found in sample statically.
            if not dis.is_loaded(ptr):
                continue

            try:
                string = ctx.memory.read_string(ptr, wide=api_name.endswith("W"))
                yield ptr, string
                seen.add(ptr)
            except UnicodeDecodeError:
                continue


def is_library_string(dis: dragodis.Disassembler, address: int) -> bool:
    """
    Attempts to determine whether the string at the given address is only used in library functions.

    :param dis: Dragodis disassembler
    :param address: Address pointing to string.
    :return:
    """
    found_function = False
    for ref in dis.references_to(address):
        try:
            func = dis.get_function(ref.from_address)
        except dragodis.NotExistError:
            continue
        found_function = True
        if not func.is_library:
            return False
    return found_function


def is_code_string(dis: dragodis.Disassembler, address: int, *, code_segment=None):
    """
    Determines whether the string has a reference to an instruction in the code segment.

    :param dis: Dragodis disassembler
    :param address: Address of the string
    :param code_segment: Segment containing instruction code.
        (Determined using entry point if not provided)
    :return:
    """
    if not code_segment:
        code_segment = dis.get_segment(dis.entry_point)
    return any(ref.from_address in code_segment for ref in dis.references_to(address))


def find_user_strings(
        dis: dragodis.Disassembler, min_length=3, ignore_api=True, ignore_library=True, printable=True, unique=False,
        in_code=True,
) -> Iterable[Tuple[int, str]]:
    """
    Finds user strings that are used within the code segment.

    :param dis: Dragodis disassembler
    :param min_length: The minimum length to count as a string.
    :param ignore_api: Whether to attempt to ignore strings used for API resolution (e.g. GetProcAddress parameters)
        NOTE: This can be slow. Disable this option if performance is a concern.
    :param ignore_library: Whether to ignore strings only used in library functions.
    :param printable: Whether to only include strings printable as ASCII.
    :param unique: Whether to only include the first instance of a string.
        (ie. ignore the same string just with a different addresses)
    :param in_code: Whether to only include strings referenced in the main user code.

    :yields: (address, string)
    """
    seen = set()
    code_segment = dis.get_segment(dis.entry_point)
    api_strings = None

    for entry in dis.strings(min_length):
        string = str(entry)

        if unique:
            if string in seen:
                continue
            seen.add(string)

        # NOTE: Using string.printable set over str.isprintable() since the latter doesn't count whitespace characters like \n
        if printable and not all(c in printable_chars for c in string):
            continue

        if in_code and not is_code_string(dis, entry.address, code_segment=code_segment):
            continue

        if ignore_library and is_library_string(dis, entry.address):
            continue

        if ignore_api:
            if api_strings is None:
                api_strings = list(find_api_resolve_strings(dis))
            if any(address == entry.address for address, _ in api_strings):
                continue

        yield entry.address, string


def _num_raw_bytes(string: str) -> int:
    """
    Returns the number of raw bytes found in the given unicode string
    """
    count = 0
    for char in string:
        char = char.encode("unicode-escape")
        count += char.startswith(b"\\x") + char.startswith(b"\\u") * 2
    return count


def detect_encoding(data: bytes, code_pages=None) -> str:
    """
    Detects the best guess string encoding for the given data.
    NOTE: This will default to "latin1" as a fallback.

    :param data: Data to detect encoding
    :param code_pages: List of possible codecs to try.
        There is a default, but feel free to provide your own.

    :returns: Decoded string and encoding used.
    """
    if code_pages is None:
        code_pages = CODE_PAGES
    best_score = len(data)  # lowest score is best
    best_code_page = None
    best_output = None
    for code_page in code_pages:
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

        score = _num_raw_bytes(output)
        if not best_output or score < best_score:
            best_score = score
            best_output = output
            best_code_page = code_page

    if best_output:
        return best_code_page

    # We shouldn't hit here since "latin1" should at least hit, but just incase...
    return "unicode_escape"


def force_to_string(data: bytes, code_pages=None) -> str:
    """
    Forces given bytes into a string using best guess encoding.

    :param data: Bytes to convert to string.
    :param code_pages: List of possible codecs to try.
        There is a default, but feel free to provide your own.

    :return: Decoded string.
    """
    if code_pages is None:
        code_pages = CODE_PAGES
    try:
        return data.decode(detect_encoding(data, code_pages=code_pages))
    except UnicodeDecodeError:
        return data.decode("latin1")


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
        self.encoding = encoding or detect_encoding(dec_data)
        self.enc_source = enc_source
        self.dec_source = dec_source

    def __str__(self):
        """
        Detects and decodes string data.
        """
        return self.data.decode(self.encoding).rstrip("\x00")

    def __bytes__(self):
        return self.data

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
