from rugosa.emulation.emulator import Emulator


def test_function_arg(disassembler):
    """Tests FunctionArg object."""
    emulator = Emulator(disassembler)

    xor_func_ea = 0x00401000
    xor_func_call = 0x0040103A

    # Basic tests.
    context = emulator.context_at(xor_func_call)
    args = context.function_args
    assert len(args) == 2
    assert args[0].name in ("a1", "param_1")
    assert args[0].type == "byte *"
    assert args[0].value == 0x0040C000  # pointer to b'Idmmn!Vnsme '
    assert args[0].addr == context.sp + 0
    assert args[1].name in ("a2", "param_2")
    assert args[1].type in ("char", "byte", "int")
    assert args[1].value == 1  # key
    assert args[1].addr == context.sp + 4
    # Test that we can change the values.
    args[0].value = 0xffff
    assert args[0].value == 0xffff
    assert args[0].addr == context.sp + 0
    assert context.memory.read(args[0].addr, 4) == b'\xff\xff\x00\x00'

    # Test pulling in passed in arguments.
    context = emulator.context_at(0x00401011)  # somewhere randomly in the xor function
    args = context.passed_in_args
    assert args[0].name in ("a1", "param_1")
    assert args[0].type == "byte *"
    assert args[0].value == 0
    assert args[0].addr == context.sp + 0x08  # +8 to account for pushed in return address and ebp
    assert args[1].name in ("a2", "param_2")
    assert args[1].type in ("char", "byte", "int")
    assert args[1].value == 0
    assert args[1].addr == context.sp + 0x0C


def test_function_arg_arm(disassembler):
    """Tests FunctionArg object."""
    emulator = Emulator(disassembler)

    xor_func_ea = 0x104FC
    xor_func_call = 0x1046C

    # Basic tests.
    context = emulator.context_at(xor_func_call)
    args = context.function_args
    assert len(args) == 2
    assert args[0].name in ("result", "__block")
    assert args[0].type in ("byte *", "char *")
    assert args[0].value == context.registers.r0 == 0x21028  # pointer to b'Idmmn!Vnsme '
    assert args[0].addr is None  # register arguments don't have an address.
    assert args[1].name in ("a2", "__edflag")
    assert args[1].type in ("char", "int")
    assert args[1].value == context.registers.r1 == 1  # key
    assert args[1].addr is None
    # Test that we can change the values.
    args[0].value = 0xffff
    assert args[0].value == context.registers.r0 == 0xffff
    assert args[0].addr is None

    # Test pulling in passed in arguments.
    context = emulator.context_at(0x1042C)  # somewhere randomly in the xor function
    args = context.passed_in_args
    assert args[0].name in ("result", "__block")
    assert args[0].type in ("byte *", "char *")
    assert args[0].value == context.registers.r0 == 0
    assert args[0].addr is None
    assert args[1].name in ("a2", "__edflag")
    assert args[1].type in ("char", "int")
    assert args[1].value == context.registers.r1 == 0
    assert args[1].addr is None


# Must be run last because it modifies the function signature.
def test_function_signature(disassembler):
    """Tests FunctionSignature object."""
    emulator = Emulator(disassembler)
    xor_func_ea = 0x00401000

    # Basic tests.
    context = emulator.context_at(xor_func_ea)
    func_sig = context.get_function_signature(func_ea=xor_func_ea)
    assert func_sig.declaration in (
        "_BYTE *__cdecl sub_401000(_BYTE *a1, char a2);",
        "undefined cdecl FUN_00401000(byte * param_1, byte param_2)"
    )
    assert func_sig.calling_convention == "__cdecl"
    assert func_sig.return_type in ("byte *", "undefined")
    args = func_sig.arguments
    assert len(args) == 2
    assert [(arg.type, arg.name, arg.value) for arg in args] in (
        [
            ("byte *", "a1", 0),
            ("char", "a2", 0),
        ],
        [
            ("byte *", "param_1", 0),
            ("byte", "param_2", 0)
        ]
    )

    # Test that we can manipulate signature.
    func_sig.add_argument("int")
    func_sig.arguments[-1].name = "new_arg"
    assert func_sig.declaration in (
        "_BYTE *__cdecl sub_401000(_BYTE *a1, char a2, INT new_arg);",
        "undefined cdecl FUN_00401000(byte * param_1, byte param_2, int new_arg)",
    )
    args = func_sig.arguments
    assert len(args) == 3
    assert args[2].name == "new_arg"
    assert args[2].type == "int"
    assert args[2].value == 0

    # Now test using iter_function_args

    # First force an incorrect number of arguments.
    func_sig.remove_argument(-1)
    func_sig.remove_argument(-1)
    assert len(func_sig.arguments) == 1
    # idc.SetType(xor_func_ea, " _BYTE *__cdecl sub_401000(_BYTE *a1)")
    # func = utils.Function(xor_func_ea)
    func = disassembler.get_function(xor_func_ea)

    # Test that it is permanently changed.
    func_sig = context.get_function_signature(xor_func_ea)
    assert len(func_sig.arguments) == 1

    # Then test we can force 2 arguments anyway.
    results = []
    for ea in func.calls_to:
        for context in emulator.iter_context_at(ea):
            args = context.get_function_arg_values(num_args=2)
            assert len(args) == 2
            # Casting is necessary if emulator is teleported.
            results.append(list(args))
    assert results == [
        [4243456, 1],
        [4243472, 2],
        [4243500, 3],
        [4243548, 4],
        [4243584, 5],
        [4243616, 6],
        [4243652, 19],
        [4243696, 23],
        [4243732, 26],
        [4243744, 35],
        [4243760, 39],
        [4243768, 64],
        [4243776, 70],
        [4243804, 115],
        [4243828, 117],
        [4243868, 119],
        [4243908, 122],
        [4243960, 127],
    ]

    # TODO: Forcing function signatures at non-function locations is not available.
    # # Test that we can force function signatures.
    # with pytest.raises(NotExistError):
    #     context.get_function_args(0xFFF)
    # with pytest.raises(NotExistError):
    #     context.get_function_signature(0xFFF)
    # assert len(context.get_function_args(0xFFF, num_args=3)) == 3
    # # Now see how signature was set to 3 integer arguments as expected.
    # func_sig = context.get_function_signature(0xFFF, force=True)
    # assert func_sig.declaration == 'int __cdecl no_name(INT, INT, INT);'
