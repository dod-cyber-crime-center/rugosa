from rugosa.emulation.constants import WIDE_STRING
from rugosa.emulation.emulator import Emulator
from rugosa.emulation.call_hooks.stdlib import libc


src = 0x123000
dst = 0x124000


def test_strcat(disassembler):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    context.memory.write(src, b"world")
    context.memory.write(dst, b"hello")
    assert libc.strcat(context, "strcat", [dst, src]) == dst
    assert context.memory.read_data(dst) == b"helloworld"
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"world".encode(encoding))
        context.memory.write(dst, u"hello".encode(encoding))
        assert libc.strcat(context, "wcscat", [dst, src]) == dst
        assert context.memory.read_data(dst, data_type=WIDE_STRING) == u"helloworld".encode(encoding)


def test_strncat(disassembler):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    context.memory.write(src, b"world")
    context.memory.write(dst, b"hello")
    assert libc.strncat(context, "strncat", [dst, src, 10]) == dst
    assert context.memory.read_data(dst) == b"helloworld"
    assert libc.strncat(context, "strncat", [dst, src, 2]) == dst
    assert context.memory.read_data(dst) == b"helloworldwo"
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"world".encode(encoding))
        context.memory.write(dst, u"hello".encode(encoding))
        assert libc.strncat(context, "wcsncat", [dst, src, 10]) == dst
        assert context.memory.read_data(dst, data_type=WIDE_STRING) == u"helloworld".encode(encoding)
        assert libc.strncat(context, "wcsncat", [dst, src, 2]) == dst
        assert context.memory.read_data(dst, data_type=WIDE_STRING) == u"helloworldwo".encode(encoding)


def test_strcpy(disassembler):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    context.memory.write(src, b"world")
    context.memory.write(dst, b"hello!!!")
    assert libc.strcpy(context, "strcpy", [dst, src]) == dst
    assert context.memory.read_data(dst) == b"world"
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"world".encode(encoding))
        context.memory.write(dst, u"hello!!!".encode(encoding))
        assert libc.strcpy(context, "wcscpy", [dst, src]) == dst
        assert context.memory.read_data(dst, data_type=WIDE_STRING) == u"world".encode(encoding)


def test_strncpy(disassembler):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    context.memory.write(src, b"world")
    context.memory.write(dst, b"hello!!!")
    assert libc.strncpy(context, "strncpy", [dst, src, 2]) == dst
    # Since we are only copying 2 characters over, the null doesn't get sent over and therefore get
    # some of the original string in the copy.
    assert context.memory.read_data(dst) == b"wollo!!!"
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"world".encode(encoding))
        context.memory.write(dst, u"hello!!!".encode(encoding))
        assert libc.strncpy(context, "wcsncpy", [dst, src, 2]) == dst
        assert context.memory.read_data(dst, data_type=WIDE_STRING) == u"wollo!!!".encode(encoding)


def test_strdup_strndup(disassembler):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    heap_ptr = context.memory._heap_base
    context.memory.write(src, b"hello")
    # should return a newly allocated string
    assert libc.strdup(context, "strdup", [src]) == heap_ptr
    assert context.memory.read_data(heap_ptr) == b"hello"
    context = emulator.new_context()
    context.memory.write(src, b"hello")
    assert libc.strndup(context, "strndup", [src, 2]) == heap_ptr
    assert context.memory.read_data(heap_ptr) == b"he"


def test_strlen(disassembler):
    emulator = Emulator(disassembler)
    context = emulator.new_context()
    context.memory.write(src, b"hello")
    assert libc.strlen(context, "strlen", [src]) == 5
    for encoding in ["utf-16-le", "utf-16-be"]:
        context = emulator.new_context()
        context.memory.write(src, u"hello".encode(encoding))
        assert libc.strlen(context, "wcslen", [src]) == 5