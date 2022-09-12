from rugosa.emulation.emulator import Emulator


def test_func_emulate(disassembler):
    """Tests full function emulation in Emulator.create_emulated."""
    emulator = Emulator(disassembler)

    if emulator.arch == "x86":
        xor_func_ea = 0x00401000
        enc_data_ptr = 0x0040C000  # pointer to b'Idmmn!Vnsme '
    else:
        xor_func_ea = 0x000103FC
        enc_data_ptr = 0x00021028
    xor_decrypt = emulator.create_emulated(xor_func_ea)

    # Test decrypting a string in memory.
    context = emulator.new_context()
    ret = xor_decrypt(enc_data_ptr, 1, context=context)
    # TODO: The encrypt() function we are emulating doesn't actually return anything.
    #   This originally worked because the x86 sample would use eax to store the length anyway.
    #   This is not the case for ARM.
    #   Update strings.c and compiled samples to have the encrypt() function return the length?
    #   (or create another sample entirely)
    # assert ret == enc_data_ptr + len(b'Idmmn!Vnsme ')  # function returns pointer after decryption.
    assert context.memory.read_data(enc_data_ptr) == b"Hello World!"

    # Test decrypting a string that was never in the sample.
    enc_data = b"!; '0607!)"
    context = emulator.new_context()
    ptr = context.memory.alloc(len(enc_data))
    context.memory.write(ptr, enc_data)
    xor_decrypt(ptr, 0x42, context=context)
    assert context.memory.read_data(ptr) == b"cybertruck"


def test_function_hooking_all(disassembler):
    """Tests function hooking mechanism."""
    emulator = Emulator(disassembler)

    if emulator.arch == "x86":
        xor_func_ea = 0x00401000
        end_ea = 0x00401141  # address in caller after all xor functions have been called.
        expected_args = [
            [0x40c000, 0x1],
            [0x40c010, 0x2],
            [0x40c02c, 0x3],
            [0x40c05c, 0x4],
            [0x40c080, 0x5],
            [0x40c0a0, 0x6],
            [0x40c0c4, 0x13],
            [0x40c0f0, 0x17],
            [0x40c114, 0x1a],
            [0x40c120, 0x23],
            [0x40c130, 0x27],
            [0x40c138, 0x40],
            [0x40c140, 0x46],
            [0x40c15c, 0x73],
            [0x40c174, 0x75],
            [0x40c19c, 0x77],
            [0x40c1c4, 0x7a],
            [0x40c1f8, 0x7f],
        ]
    else:
        xor_func_ea = 0x000103FC
        end_ea = 0x00010540
        expected_args = [
            [0x21028, 0x1],
            [0x21038, 0x2],
            [0x21054, 0x3],
            [0x21084, 0x4],
            [0x210A8, 0x5],
            [0x210C8, 0x6],
            [0x210EC, 0x13],
            [0x21118, 0x17],
            [0x2113C, 0x1a],
            [0x21148, 0x23],
            [0x21158, 0x27],
            [0x21160, 0x40],
            [0x21168, 0x46],
            [0x21184, 0x73],
            [0x2119C, 0x75],
            [0x211C4, 0x77],
            [0x211EC, 0x7a],
            [0x2121C, 0x7f],
        ]

    args = []
    # First test hooking with standard function.
    def xor_hook(context, func_name, func_args):
        args.append(func_args)
    emulator.hook_call(xor_func_ea, xor_hook)
    context = emulator.context_at(end_ea)
    # Casting is necessary if emulator is teleported.
    args = [list(func_args) for func_args in args]
    assert args == expected_args
    assert [list(_args) for _, _args in context.get_call_history(xor_func_ea)] == expected_args

    # Now test with the function emulated to see our data getting decrypted.
    emulator.reset_hooks()
    emulator.emulate_call(xor_func_ea)
    context = emulator.context_at(end_ea)
    assert [list(_args) for _, _args in context.get_call_history(xor_func_ea)] == expected_args
    strings = [(context.memory.read_data(args[0]), args[1]) for _, args in context.get_call_history(xor_func_ea)]
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


def test_instruction_hooking_x86(disassembler):
    emulator = Emulator(disassembler)

    # Test hooking all "push" instructions, which will be the parameters to the xor decryption.
    pushes = []
    def push_hook(context, instruction):
        pushes.append(instruction.operands[0].value)
    emulator.hook_instruction("push", push_hook)
    context = emulator.context_at(0x00401142)
    # fmt: off
    assert pushes == [
        0x117fc00,  # ebp pushed
        # key, enc_data_ptr
        0x1, 0x40c000,
        0x2, 0x40c010,
        0x3, 0x40c02c,
        0x4, 0x40c05c,
        0x5, 0x40c080,
        0x6, 0x40c0a0,
        0x13, 0x40c0c4,
        0x17, 0x40c0f0,
        0x1a, 0x40c114,
        0x23, 0x40c120,
        0x27, 0x40c130,
        0x40, 0x40c138,
        0x46, 0x40c140,
        0x73, 0x40c15c,
        0x75, 0x40c174,
        0x77, 0x40c19c,
        0x7a, 0x40c1c4,
        0x7f, 0x40c1f8,
    ]
    # fmt: on



def test_instruction_hooking_arm(disassembler):
    emulator = Emulator(disassembler)

    # Test hooking all LDR instructions, which will be the encrypted string pointers.
    ldrs = []
    def ldr_hook(context, instruction):
        ldrs.append(instruction.operands[1].value)
    emulator.hook_instruction("ldr", ldr_hook)
    emulator.context_at(0x10540)
    # fmt: off
    assert ldrs == [
        0x21028,
        0x21038,
        0x21054,
        0x21084,
        0x210A8,
        0x210C8,
        0x210EC,
        0x21118,
        0x2113C,
        0x21148,
        0x21158,
        0x21160,
        0x21168,
        0x21184,
        0x2119C,
        0x211C4,
        0x211EC,
        0x2121C,
    ]
    # fmt: on


def test_opcode_hooking(disassembler):
    emulator = Emulator(disassembler)

    # Test hooking all "push" instructions.
    pushes = []
    def push(context, instruction):
        operand = instruction.operands[0]
        value_bytes = operand.value.to_bytes(operand.width, context.byteorder)
        context.sp -= context.byteness
        context.memory.write(context.sp, value_bytes)
        pushes.append(operand.value)  # record for testing

    emulator.hook_opcode("push", push)

    context = emulator.context_at(0x00401142)
    # fmt: off
    assert pushes == [
        0x117fc00,  # ebp pushed
        # key, enc_data_ptr
        0x1, 0x40c000,
        0x2, 0x40c010,
        0x3, 0x40c02c,
        0x4, 0x40c05c,
        0x5, 0x40c080,
        0x6, 0x40c0a0,
        0x13, 0x40c0c4,
        0x17, 0x40c0f0,
        0x1a, 0x40c114,
        0x23, 0x40c120,
        0x27, 0x40c130,
        0x40, 0x40c138,
        0x46, 0x40c140,
        0x73, 0x40c15c,
        0x75, 0x40c174,
        0x77, 0x40c19c,
        0x7a, 0x40c1c4,
        0x7f, 0x40c1f8,
    ]
    # fmt: on
