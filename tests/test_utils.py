"""
Tests utility functions.
"""

from rugosa.emulation import utils


def test_signed():
    assert utils.signed(1, 4) == 1
    assert utils.signed(0xffffff10, 4) == -240


def test_unsigned():
    assert utils.unsigned(1, 4) == 1
    assert utils.unsigned(-240, 4) == 0xffffff10


def test_sign_bit():
    assert utils.sign_bit(1, 4) == 0
    assert utils.sign_bit(0xffffff10, 4) == 1


def test_sign_extend():
    assert utils.sign_extend(1, 4, 8) == 1
    assert utils.sign_extend(0xffffff10, 4, 8) == 0xffffffffffffff10


def test_float_to_int():
    assert utils.float_to_int(1.0) == 0x3ff0000000000000


def test_int_to_float():
    assert utils.int_to_float(0x3ff0000000000000) == 1.0


def test_get_mask():
    assert utils.get_mask(4) == 0xffffffff


def test_sanitize_func_name():
    assert utils.sanitize_func_name("sprintf") == "sprintf"
    assert utils.sanitize_func_name("_sprintf") == "sprintf"
    assert utils.sanitize_func_name("_sprintf_2") == "sprintf"


def test_is_func_ptr(disassembler):
    assert utils.is_func_ptr(disassembler, 0x401000)
    assert utils.is_func_ptr(disassembler, 0x40A040)
    assert not utils.is_func_ptr(disassembler, 0x1)
