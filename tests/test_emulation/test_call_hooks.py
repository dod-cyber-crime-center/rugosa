from rugosa.emulation.constants import WIDE_STRING
from rugosa.emulation.emulator import Emulator
from rugosa.emulation.call_hooks import stdlib


src = 0x123000
dst = 0x124000


def test_strcat(disassembler):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    context.memory.write(src, b"world")
    context.memory.write(dst, b"hello")
    assert stdlib.strcat(context, "strcat", [dst, src]) == dst
    assert context.memory.read_data(dst) == b"helloworld"
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"world".encode(encoding))
        context.memory.write(dst, u"hello".encode(encoding))
        assert stdlib.strcat(context, "wcscat", [dst, src]) == dst
        assert context.memory.read_data(dst, data_type=WIDE_STRING) == u"helloworld".encode(encoding)


def test_strncat(disassembler):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    context.memory.write(src, b"world")
    context.memory.write(dst, b"hello")
    assert stdlib.strncat(context, "strncat", [dst, src, 10]) == dst
    assert context.memory.read_data(dst) == b"helloworld"
    assert stdlib.strncat(context, "strncat", [dst, src, 2]) == dst
    assert context.memory.read_data(dst) == b"helloworldwo"
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"world".encode(encoding))
        context.memory.write(dst, u"hello".encode(encoding))
        assert stdlib.strncat(context, "wcsncat", [dst, src, 10]) == dst
        assert context.memory.read_data(dst, data_type=WIDE_STRING) == u"helloworld".encode(encoding)
        assert stdlib.strncat(context, "wcsncat", [dst, src, 2]) == dst
        assert context.memory.read_data(dst, data_type=WIDE_STRING) == u"helloworldwo".encode(encoding)


def test_strcpy(disassembler):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    context.memory.write(src, b"world")
    context.memory.write(dst, b"hello!!!")
    assert stdlib.strcpy(context, "strcpy", [dst, src]) == dst
    assert context.memory.read_data(dst) == b"world"
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"world".encode(encoding))
        context.memory.write(dst, u"hello!!!".encode(encoding))
        assert stdlib.strcpy(context, "wcscpy", [dst, src]) == dst
        assert context.memory.read_data(dst, data_type=WIDE_STRING) == u"world".encode(encoding)


def test_strncpy(disassembler):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    context.memory.write(src, b"world")
    context.memory.write(dst, b"hello!!!")
    assert stdlib.strncpy(context, "strncpy", [dst, src, 2]) == dst
    # Since we are only copying 2 characters over, the null doesn't get sent over and therefore get
    # some of the original string in the copy.
    assert context.memory.read_data(dst) == b"wollo!!!"
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"world".encode(encoding))
        context.memory.write(dst, u"hello!!!".encode(encoding))
        assert stdlib.strncpy(context, "wcsncpy", [dst, src, 2]) == dst
        assert context.memory.read_data(dst, data_type=WIDE_STRING) == u"wollo!!!".encode(encoding)


def test_strdup_strndup(disassembler):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    heap_ptr = context.memory._heap_base
    context.memory.write(src, b"hello")
    # should return a newly allocated string
    assert stdlib.strdup(context, "strdup", [src]) == heap_ptr
    assert context.memory.read_data(heap_ptr) == b"hello"
    context = emulator.new_context()
    context.memory.write(src, b"hello")
    assert stdlib.strndup(context, "strndup", [src, 2]) == heap_ptr
    assert context.memory.read_data(heap_ptr) == b"he"


def test_strlen(disassembler):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    context.memory.write(src, b"hello")
    assert stdlib.strlen(context, "strlen", [src]) == 5
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"hello".encode(encoding))
        assert stdlib.strlen(context, "wcslen", [src]) == 5