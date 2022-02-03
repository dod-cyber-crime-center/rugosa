
from rugosa import re


def test_match(disassembler):
    ptn = re.compile(b"\x56\x56\x56\x56\x56\xe8\x9c\x12\x00\x00")
    match = ptn.search(disassembler)
    assert match
    assert match.start() == 0x4012c5
    funcs = list(re.find_functions(ptn, disassembler))
    assert len(funcs) == 1
    assert funcs[0].start == 0x4012a0
