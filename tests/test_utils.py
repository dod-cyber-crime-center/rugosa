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
    assert utils.sanitize_func_name("__imp_CreateFile") == "CreateFile"


def test_is_func_ptr(disassembler):
    assert utils.is_func_ptr(disassembler, 0x401000)
    assert utils.is_func_ptr(disassembler, 0x40A040)
    assert not utils.is_func_ptr(disassembler, 0x1)


def test_cached_generator():
    triggerred = 0
    @utils.cached_generator
    def mygenerator(count):
        nonlocal triggerred
        for i in range(count):
            triggerred += 1
            yield i

    gen = mygenerator(5)
    assert next(gen) == 0
    assert next(gen) == 1
    assert triggerred == 2

    gen2 = mygenerator(5)
    assert next(gen2) == 0
    assert next(gen2) == 1
    assert triggerred == 2  # original generator not triggered
    assert next(gen2) == 2
    assert triggerred == 3  # now it is

    assert next(gen) == 2
    assert triggerred == 3  # used cache

    triggerred = 0
    gen3 = mygenerator(6)
    assert next(gen3) == 0
    assert next(gen3) == 1
    assert triggerred == 2

    # Test cache invalidation.
    triggerred = 0
    assert next(mygenerator(5)) == 0
    assert next(mygenerator(6)) == 0
    assert triggerred == 0
    mygenerator.clear_cache()
    assert next(mygenerator(5)) == 0
    assert next(mygenerator(6)) == 0
    assert triggerred == 2
