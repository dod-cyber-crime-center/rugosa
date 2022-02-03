import pytest

from rugosa.emulation.emulator import Emulator
from rugosa.emulation.constants import DWORD, BYTE


def test_cpu_context_x86(disassembler):
    emulator = Emulator(disassembler)

    # Test on encryption function.
    context = emulator.context_at(0x00401024)

    operands = context.operands
    assert len(operands) == 2

    assert "ebp" in operands[0].text.casefold()
    assert operands[0].value == 0
    # arg_0 should be 8 bytes from stack pointer.
    assert operands[0].addr == context.registers.esp + 8 == context.registers.ebp + 8 == 0x117F804

    assert operands[1].text.casefold() == "eax"
    assert operands[1].value == context.registers.eax == 1

    # Test variables
    data_ptr = operands[0].addr
    assert sorted(context.variables.names) in (
        ["arg_0", "arg_4"],
        ["param_1", "param_2"],
    )
    assert data_ptr in context.variables
    var = context.variables[data_ptr]
    assert var.name in ("arg_0", "param_1")
    assert not var.history
    assert var.size == 4
    assert var.data_type in ("int", "byte *")
    assert var.data_type_size == 4
    assert var.count == 1
    # test changing the variable
    assert var.data == b"\x00\x00\x00\x00"
    assert var.value == context.operands[0].value == 0
    var.value = 21
    assert var.value == context.operands[0].value == 21
    assert var.data == b"\x15\x00\x00\x00"
    assert context.memory.read(var.addr, 4) == b"\x15\x00\x00\x00"

    # Now execute this instruction and see if a1 has be set with the 1 from eax.
    context.execute(context.ip)
    assert operands[0].value == 1

    # Test getting all possible values passed into arg_0 using depth.
    strings = []
    for context in emulator.iter_context_at(0x00401003, depth=1):
        assert context.ip == 0x00401003
        # mov     eax, [ebp+arg_0]
        strings.append(context.memory.read_data(context.operands[1].value))
    assert strings == [
        b"Idmmn!Vnsme ",
        b'Vgqv"qvpkle"ukvj"ig{"2z20',
        b"Wkf#rvj`h#aqltm#el{#ivnsp#lufq#wkf#obyz#gld-",
        b"Keo$mw$wpvkjc$ej`$ehwk$cmraw$wle`a*",
        b"Dfla%gpwkv%mji`v%lk%rjji%fijqm+",
        b"Egru&ghb&biau&cgen&ngrc&rnc&irnct(",
        b"\\cv}3g{v3pargv3qfg3w|}4g3qavrx3g{v3t\x7fr``=",
        b"C\x7frer7c\x7fr7q{xxs7zve|7~d7cry7~yt\x7frd9",
        b'+()./,-"#*',
        b"`QFBWFsQL@FPPb",
        b"tSUdFS",
        b"\x01\x13\x10n\x0e\x05\x14",
        b'-",5 , v,tr4v,trv4t,v\x7f,ttt',
        b"@AKJDGBA@KJGDBJKAGDC",
        (
            b"!\x1d\x10U\x05\x14\x06\x01U\x02\x1c\x19\x19U\x19\x1a\x1a\x1eU\x17\x07\x1c"
            b"\x12\x1d\x01\x10\x07U\x01\x1a\x18\x1a\x07\x07\x1a\x02["
        ),
        (
            b"4\x16\x05\x04W\x16\x19\x13W\x15\x02\x04\x04\x12\x04W\x04\x03\x16\x1b\x1b"
            b"\x12\x13W\x1e\x19W\x04\x16\x19\x13W\x13\x05\x1e\x11\x03\x04Y"
        ),
        (
            b".\x12\x1fZ\x10\x1b\x19\x11\x1f\x0eZ\x12\x0f\x14\x1dZ\x15\x14Z\x0e\x12\x1f"
            b"Z\x18\x1b\x19\x11Z\x15\x1cZ\x0e\x12\x1fZ\r\x13\x1e\x1fZ\x19\x12\x1b\x13\x08T"
        ),
        b"LMFOGHKNLMGFOHKFGNLKHNMLOKGNKGHFGLHKGLMHKGOFNMLHKGFNLMJNMLIJFGNMLOJIMLNGFJHNM",
    ]

    # Test pulling arguments from a call.
    context = emulator.context_at(0x0040103A)
    operands = context.operands
    assert len(operands) == 1
    assert operands[0].is_func_ptr
    assert operands[0].value == 0x00401000
    # First, attempt to pull the arguments from the stack without get_function_args()
    first_arg_ptr = context.memory.read_data(context.registers.esp, data_type=DWORD)
    second_arg = context.memory.read_data(context.registers.esp + 4, data_type=BYTE)
    assert context.memory.read_data(first_arg_ptr) == b"Idmmn!Vnsme "
    assert second_arg == 1
    # Now try with get_function_args()
    args = context.get_function_arg_values()
    assert len(args) == 2
    assert context.memory.read_data(args[0]) == b"Idmmn!Vnsme "
    assert args[1] == 1

    # TODO: We removed counting function pointers as "variables".
    #   Determine if that was a good idea.
    assert len(context.variables) == 1
    assert 0x40c000 in context.variables
    var = context.variables[0x40c000]
    assert var.name in ("aIdmmnVnsme", "s_Idmmn!Vnsme_0040c000")

    # Test getting context with follow_loops by pulling context at end of xor algorithm.

    # first without follow_loops off to show we get non-decrypted data
    context = emulator.context_at(0x00401029, follow_loops=False, depth=1)
    assert context.passed_in_args[1].value == 0x1  # key
    assert context.memory.read_data(context.passed_in_args[0].value) == b"Idmmn!Vnsme "

    # now with follow_loops on to show we get decrypted data
    context = emulator.context_at(0x00401029, follow_loops=True, depth=1)
    assert context.passed_in_args[1].value == 0x1
    # The way the xor function works is that it takes and MODIFIES the
    # pointer argument passed in, unhelpfully returning a pointer to the end of the
    # decrypted data, not the start, with no way knowing the size...
    # This is obviously a typo when creating strings.exe, but let's just say
    # this is good practice for dealing with some gnarly malware sample :)
    # Therefore, we are going to iteratively decrease the pointer until we find a
    # valid address in the variable map. This variable was the variable used by the caller.
    result = context.registers.eax
    result -= 1
    while result not in context.variables:
        result -= 1
    assert context.memory.read_data(result) == b"Hello World!"

    # Alright, one more time, but with ALL strings.
    # Testing we can successfully decrypt the strings and get the key used.
    strings = []
    for context in emulator.iter_context_at(0x00401029, follow_loops=True, depth=1):
        result = context.registers.eax
        result -= 1
        while result not in context.variables:
            result -= 1
        strings.append((context.memory.read_data(result), context.passed_in_args[1].value))
    assert strings == [
        (b'Hello World!', 0x01),
        (b'Test string with key 0x02', 0x02),
        (b'The quick brown fox jumps over the lazy dog.', 0x03),
        (b'Oak is strong and also gives shade.', 0x04),
        (b'Acid burns holes in wool cloth.', 0x05),
        (b'Cats and dogs each hate the other.', 0x06),
        (b"Open the crate but don't break the glass.", 0x13),
        (b'There the flood mark is ten inches.', 0x17),
        (b'1234567890', 0x1a),
        (b'CreateProcessA', 0x23),
        (b'StrCat', 0x27),
        (b'ASP.NET', 0x40),
        (b'kdjsfjf0j24r0j240r2j09j222', 0x46),
        (b'32897412389471982470', 0x73),
        (b'The past will look brighter tomorrow.', 0x75),
        (b'Cars and busses stalled in sand drifts.', 0x77),
        (b'The jacket hung on the back of the wide chair.', 0x7a),
        (b'32908741328907498134712304814879837483274809123748913251236598123056231895712', 0x7f),
    ]


def test_cpu_context_arm(disassembler):
    emulator = Emulator(disassembler)

    # Test on encryption function.
    context = emulator.context_at(0x10420)

    # TODO: Move to test_operands_arm()?
    operands = context.operands
    assert len(operands) == 2

    assert operands[0].text in ("R2", "r2")
    assert operands[0].value == context.registers.r2 == 1

    assert operands[1].text in ("[R11,#var_8]", "[r11,#-0x8]")
    assert operands[1].value == 0
    # var_8 should be 8 bytes from r11 and 4 bytes off sp
    expected = hex(0x117F7F4)
    # expected = hex(0x117F7F8)
    assert hex(operands[1].addr) == expected
    assert hex(context.registers.r11 - 8) == expected
    assert hex(context.registers.sp + 4) == expected

    # Test variables
    var_operand = operands[1]
    data_ptr = var_operand.addr
    assert sorted(context.variables.names) in (
        ["var_8", "var_9"],
        ["local_4", "local_c", "local_d"],
    )
    assert data_ptr in context.variables
    var = context.variables[data_ptr]
    assert var.name in ("var_8", "local_c")
    assert not var.history
    assert var.size == 4
    assert var.data_type in ("int", "byte *", "undefined4")
    assert var.data_type_size == 4
    assert var.count == 1
    # test changing the variable
    assert var.data == b"\x00\x00\x00\x00"
    assert var.value == var_operand.value == 0
    var.value = 21
    assert var.value == var_operand.value == 21
    assert var.data == b"\x15\x00\x00\x00"
    assert context.memory.read(var.addr, 4) == b"\x15\x00\x00\x00"

    # Now execute this instruction and see if a1 has be set with the 1 from R2.
    context.execute(context.ip)
    assert var_operand.value == 1

    # Test getting all possible values passed into arg_0 using depth.
    strings = []
    for context in emulator.iter_context_at(0x10408, depth=1):
        assert context.ip == 0x10408
        # STR     R0, [R11,#var_8]
        strings.append(context.memory.read_data(context.operands[0].value))
    assert strings == [
        b"Idmmn!Vnsme ",
        b'Vgqv"qvpkle"ukvj"ig{"2z20',
        b"Wkf#rvj`h#aqltm#el{#ivnsp#lufq#wkf#obyz#gld-",
        b"Keo$mw$wpvkjc$ej`$ehwk$cmraw$wle`a*",
        b"Dfla%gpwkv%mji`v%lk%rjji%fijqm+",
        b"Egru&ghb&biau&cgen&ngrc&rnc&irnct(",
        b"\\cv}3g{v3pargv3qfg3w|}4g3qavrx3g{v3t\x7fr``=",
        b"C\x7frer7c\x7fr7q{xxs7zve|7~d7cry7~yt\x7frd9",
        b'+()./,-"#*',
        b"`QFBWFsQL@FPPb",
        b"tSUdFS",
        b"\x01\x13\x10n\x0e\x05\x14",
        b'-",5 , v,tr4v,trv4t,v\x7f,ttt',
        b"@AKJDGBA@KJGDBJKAGDC",
        (
            b"!\x1d\x10U\x05\x14\x06\x01U\x02\x1c\x19\x19U\x19\x1a\x1a\x1eU\x17\x07\x1c"
            b"\x12\x1d\x01\x10\x07U\x01\x1a\x18\x1a\x07\x07\x1a\x02["
        ),
        (
            b"4\x16\x05\x04W\x16\x19\x13W\x15\x02\x04\x04\x12\x04W\x04\x03\x16\x1b\x1b"
            b"\x12\x13W\x1e\x19W\x04\x16\x19\x13W\x13\x05\x1e\x11\x03\x04Y"
        ),
        (
            b".\x12\x1fZ\x10\x1b\x19\x11\x1f\x0eZ\x12\x0f\x14\x1dZ\x15\x14Z\x0e\x12\x1f"
            b"Z\x18\x1b\x19\x11Z\x15\x1cZ\x0e\x12\x1fZ\r\x13\x1e\x1fZ\x19\x12\x1b\x13\x08T"
        ),
        b"LMFOGHKNLMGFOHKFGNLKHNMLOKGNKGHFGLHKGLMHKGOFNMLHKGFNLMJNMLIJFGNMLOJIMLNGFJHNM",
    ]

    # Test pulling arguments from a call.
    context = emulator.context_at(0x1046C)
    operands = context.operands
    assert len(operands) == 1
    assert operands[0].is_func_ptr
    assert operands[0].value == 0x103FC
    # First, attempt to pull the arguments from the registers without get_function_args()
    first_arg_ptr = context.registers.r0
    second_arg = context.registers.r1
    assert context.memory.read_data(first_arg_ptr) == b"Idmmn!Vnsme "
    assert second_arg == 1
    # Now try with get_function_args()
    args = context.get_function_arg_values()
    assert len(args) == 2
    assert context.memory.read_data(args[0]) == b"Idmmn!Vnsme "
    assert args[1] == 1

    assert sorted(context.variables.names) in (
        ["off_10544"],
        ["PTR_string01_00010544", "inlen", "string01"],
    )

    # Test getting context with follow_loops by pulling context at end of xor algorithm.

    # first without follow_loops off to show we get non-decrypted data
    context = emulator.context_at(0x10454, follow_loops=False, depth=1)
    assert context.passed_in_args[1].value == 0x1  # key
    assert context.memory.read_data(context.passed_in_args[0].value) == b"Idmmn!Vnsme "

    # now with follow_loops on to show we get decrypted data
    context = emulator.context_at(0x10454, follow_loops=True, depth=1)
    # The compiler reuses register r0, but then saves the register in the stack (var_9).
    # Therefore, attempting to use context.passed_in_args will produce garbage, because it is not aware of the reuse.
    # So lets pull from "var_9" where it saved it instead.
    assert context.passed_in_args[1].value != 0x1
    var = context.variables.get("var_9", context.variables.get("local_d"))
    assert var
    assert var.value == 1
    # Luckily, the compiler does not mess with the original first argument.
    assert context.memory.read_data(context.passed_in_args[0].value) == b"Hello World!"

    # Alright, one more time, but with ALL strings.
    # Testing we can successfully decrypt the strings and get the key used.
    strings = []
    for context in emulator.iter_context_at(0x10454, follow_loops=True, depth=1):
        var = context.variables.get("var_9", context.variables.get("local_d"))
        key = var.value
        result = context.memory.read_data(context.passed_in_args[0].value)
        strings.append((result, key))
    assert strings == [
        (b'Hello World!', 0x01),
        (b'Test string with key 0x02', 0x02),
        (b'The quick brown fox jumps over the lazy dog.', 0x03),
        (b'Oak is strong and also gives shade.', 0x04),
        (b'Acid burns holes in wool cloth.', 0x05),
        (b'Cats and dogs each hate the other.', 0x06),
        (b"Open the crate but don't break the glass.", 0x13),
        (b'There the flood mark is ten inches.', 0x17),
        (b'1234567890', 0x1a),
        (b'CreateProcessA', 0x23),
        (b'StrCat', 0x27),
        (b'ASP.NET', 0x40),
        (b'kdjsfjf0j24r0j240r2j09j222', 0x46),
        (b'32897412389471982470', 0x73),
        (b'The past will look brighter tomorrow.', 0x75),
        (b'Cars and busses stalled in sand drifts.', 0x77),
        (b'The jacket hung on the back of the wide chair.', 0x7a),
        (b'32908741328907498134712304814879837483274809123748913251236598123056231895712', 0x7f),
    ]
