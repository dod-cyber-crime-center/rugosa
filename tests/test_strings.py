import pytest

import rugosa


def test_find_string_data():
    from rugosa.strings import find_string_data

    # General test of mixture of utf-8 and utf-16
    data = b"h\x00e\x00l\x00l\x00o\x00\x00\x00\x00\x00test\x00\x00\x00joe\x00\x00w\x00o\x00r\x00l\x00d"
    assert list(find_string_data(data)) == [
        (0, b"h\x00e\x00l\x00l\x00o\x00\x00\x00", "utf-16-le"),
        (14, b"test\x00", "utf-8"),
        (21, b"joe\x00", "utf-8"),
        (25, b"\x00w\x00o\x00r\x00l\x00d", "utf-16-be"),
    ]

    # Test arbitrary number of null bytes in between strings.
    data = b"\x00\x00\x00hello\x00\x00\x00\x00\x00\x00w\x00o\x00r\x00l\x00d\x00\x00\x00\x00\x00\x00"
    assert list(find_string_data(data)) == [
        (3, b"hello\x00", "utf-8"),
        (14, b"w\x00o\x00r\x00l\x00d\x00\x00\x00", "utf-16-le"),
    ]

    # Test falling back on single character strings.
    data = b"1\x000\x00\x00\x00hello\x00world\x00"
    assert list(find_string_data(data)) == [
        (0, b"1\x000\x00\x00\x00", "utf-16-le"),
        (6, b"hello\x00", "utf-8"),
        (12, b"world\x00", "utf-8"),
    ]
    data = b"1\x000\x00hello\x00world\x00"
    assert list(find_string_data(data)) == [
        (0, b"1\x00", "utf-8"),
        (2, b"0\x00", "utf-8"),
        (4, b"hello\x00", "utf-8"),
        (10, b"world\x00", "utf-8"),
    ]


def test_force_to_string():
    assert rugosa.force_to_string(b"hello") == "hello"
    assert rugosa.force_to_string("hello".encode("utf-16-be")) == "hello"
    assert rugosa.force_to_string(b"\x4f\xdf\xc6\x4a\xbe\x0a\xff\x76") == "OßÆJ¾\nÿv"


USER_STRINGS = {
    (0x40c000, 'Idmmn!Vnsme '),
    (0x40c010, 'Vgqv"qvpkle"ukvj"ig{"2z20'),
    (0x40c02c, 'Wkf#rvj`h#aqltm#el{#ivnsp#lufq#wkf#obyz#gld-'),
    (0x40c05c, 'Keo$mw$wpvkjc$ej`$ehwk$cmraw$wle`a*'),
    (0x40c080, 'Dfla%gpwkv%mji`v%lk%rjji%fijqm+'),
    (0x40c0a0, 'Egru&ghb&biau&cgen&ngrc&rnc&irnct('),
    # (0x40c0c4, '\cv}3g{v3pargv3qfg3w|}4g3qavrx3g{v3t'),  # TODO: Ghidra fails to find this one.
    (0x40c114, '+()./,-"#*'),
    (0x40c120, '`QFBWFsQL@FPPb'),
    (0x40c130, 'tSUdFS'),
    # (0x40c140, '-",5 , v,tr4v,trv4t,v'),   # TODO: Ghidra fails to find this one.
    (0x40c15c, '@AKJDGBA@KJGDBJKAGDC'),
    (0x40c1f8, 'LMFOGHKNLMGFOHKFGNLKHNMLOKGNKGHFGLHKGLMHKGOFNMLHKGFNLMJNMLIJFGNMLOJIMLNGFJHNM'),
}


API_RESOLVE_STRINGS = {
    (0x40a838, 'KERNEL32.DLL'),
    (0x40a1d4, 'mscoree.dll'),
    (0x40a9d0, 'USER32.DLL'),
    (0x40a1c4, 'CorExitProcess'),
    (0x40a828, 'EncodePointer'),
    (0x40a854, 'DecodePointer'),
    (0x40a884, 'FlsAlloc'),
    (0x40a878, 'FlsGetValue'),
    (0x40a86c, 'FlsSetValue'),
    (0x40a864, 'FlsFree'),
    (0x40a9c4, 'MessageBoxA'),
    (0x40a9b4, 'GetActiveWindow'),
    (0x40a9a0, 'GetLastActivePopup'),
    (0x40a984, 'GetUserObjectInformationA'),
    (0x40a96c, 'GetProcessWindowStation'),
}


def test_find_user_strings(disassembler):
    strings = list(rugosa.find_user_strings(disassembler, unique=True))
    print("\n".join(f"{hex(address)}: '{string}'" for address, string in strings))
    assert set(strings) >= USER_STRINGS
    # While we could have extras based on disassembler, make sure we are somewhat on target.
    assert len(strings) == pytest.approx(len(USER_STRINGS), abs=3)
    assert set(strings).isdisjoint(API_RESOLVE_STRINGS)

    strings = list(rugosa.find_user_strings(disassembler, ignore_api=False, ignore_library=False))
    print("\n".join(f"{hex(address)}: '{string}'" for address, string in strings))
    assert set(strings) >= (USER_STRINGS | API_RESOLVE_STRINGS)


def test_find_api_resolve_strings(disassembler):
    strings = list(rugosa.find_api_resolve_strings(disassembler))
    print("\n".join(f"{hex(address)}: '{string}'" for address, string in strings))
    assert set(strings) == API_RESOLVE_STRINGS


def test_is_library_string(disassembler):
    assert rugosa.is_library_string(disassembler, 0x40A838)
    assert rugosa.is_library_string(disassembler, 0x40A884)
    assert not rugosa.is_library_string(disassembler, 0x40C000)


def test_is_code_string(disassembler):
    assert rugosa.is_code_string(disassembler, 0x40A838)
    assert rugosa.is_code_string(disassembler, 0x40C000)
    assert not rugosa.is_code_string(disassembler, 0x40B2D4)
