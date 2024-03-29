# CPU Emulation

Rugosa includes a function tracing utility that, along with Dragodis, can be used to statically emulate
and trace instructions within a function.

- [Creating an Emulator](#creating-an-emulator)
- [Creating a ProcessorContext](#creating-a-processorcontext)
- [Iterating Multiple Paths](#iterating-multiple-paths)
- [Emulating Call Stack](#emulating-call-stack)
- [Emulating Loops](#emulating-loops)
- [Retrieving Function Arguments](#retrieving-function-arguments)
- [Modifying Function Signature](#modifying-function-signature)
- [Emulating Subroutines](#emulating-subroutines)
- [Hooking Functions](#hooking-functions)
- [Hooking Instructions](#hooking-instructions)
- [Hooking Opcodes](#hooking-opcodes)
- [Pointer History](#pointer-history)
- [Variables](#variables)
- [Objects](#objects)
- [Actions](#actions)


## Creating an Emulator

To start, first create an `Emulator` object with an open Dragodis disassembler object.

This object can accept options to control how emulation is processed, such as setting `max_instructions` for the `follow_loops` feature or to turn off the branch tracking feature.

```python
import dragodis
import rugosa

with dragodis.open_program(r"C:\input.exe") as dis:
    # First create an Emulator object.
    emulator = rugosa.Emulator(dis)
```

## Creating a ProcessorContext

We can emulate the function up to a particular instruction address (but not including) by requesting the context. 
For a simple function, we most likely will only care about the first possible
code path to get to that instruction. In which case we can use the `context_at()` function.

If emulation is successful, a `ProcessorContext` object will be returned.
This object can be used to extract information about its registers, operands, and memory at that point in time.
If the given instruction is a `call` operation, the passed in arguments can also be retrieved.

- Operands are a special `Operand` object that can be used to query information about the operand (`type`, `text`, `has_register()`, etc) and holds the dereferenced `value` and the source `addr` if it's a memory reference.
- Memory can be retrieved with the `read_data()` function.

```python
import dragodis
import rugosa
from rugosa.emulation import constants

with dragodis.open_program(r"C:\input.exe") as dis:
   emulator = rugosa.Emulator(dis)
   
   context = emulator.context_at(addr)
   
   # extract the first operand at addr
   operand = context.operands[0]  # equivalent to context.get_operands(addr)[0]
   # pull referenced address if memory reference or value otherwise
   ptr = operand.addr or operand.value  
   # extract data from pointer 
   data = context.memory.read_data(ptr) # as null terminated string
   data = context.memory.read_data(ptr, data_type=constants.WIDE_STRING)  # as null terminated wide string
   data = context.memory.read_data(ptr, 12)  # as 12 bytes
   data = context.memory.read_data(ptr, data_type=constants.DWORD)  # as dword
   # etc.
   
   # Extract operand from a different instruction.
   operand = context.get_operands(addr - 8)[0]
   
   # Extract pointer from register and read contents from memory.
   rbp = context.registers.rbp
   stack = context.memory.read_data(rbp, size=0x14)
   
   # Extract the arguments (if a call instruction)
   for args in context.get_function_arg_values():
       for i, arg in enumerate(args):
           print("Arg {} -> 0x{:X}".format(i, arg))
           # If arg is a pointer, you can use the context to dereference it.
           value = context.memory.read_data(arg, size=100)
```

*WARNING: If using IDA, the emulator will use the Hex-Rays Decompiler to help get more accurate function signatures for the `get_function_args()`.
You are more likely to get an incorrect number of arguments if it's not available.*


As a shortcut, extracting the operand value or function arguments can be done directly
from the `Emulator` object with a single call.
Both the extracted value and the context are returned.

```python
# (automatically pulls operand.addr or operand.value as appropriate)
context, value = emulator.get_operand_value(addr, 0)

# Get function arguments for a call instruction.
for context, args in emulator.get_function_args(addr):
    for i, arg in enumerate(args):
        print("Arg {} -> 0x{:X}".format(i, arg))
        # If arg is a pointer, you can use the context to dereference it.
        value = context.memory.read(arg, size=100)
```

## Iterating Multiple Paths

If you would like to retrieve the context, operands, or function arguments for all possible code paths we can
use the `iter_context_at()`, `iter_operand_value()` or `iter_function_args()` functions within the
`Emulator` object.

*WARNING: It is possible to retrieve an unmanageable amount of possible code paths. It is recommended to break
out of the for loop as soon as you extracted the data you need.*

```python
# Get context for each possible path.
for context in emulator.iter_context_at(addr):
    # ...
    
# Get operand for each possible path.
for context, value in emulator.iter_operand_value(addr):
    # ...
    
# Get function args for each possible path.
for context, args in emulator.iter_function_args(addr):
    # ...    
```

## Emulating Call Stack

By default, when you request a context, operand, or function argument, the emulation will
start at the top of the function for that tracer. If you would like to have the callers of that
function to also be emulated beforehand you can specify the depth of the call stack using the `depth` parameter.

When used with an `iter*` function, this will cause a context to be created for all possible call stacks
of the specified depth and all possible code paths for each of the call levels.
To use only the first possible code path for each call level, you can set the `exhaustive` parameter
to be `False`.

```python
# Get context for each possible path allowing a call stack of 2 previous callers.
for context in emulator.iter_context_at(addr, depth=2, exhaustive=False):
    # ...
```

This can be useful if you are trying to pull all possible values for a passed in argument or to automatically handle possible wrapper functions.

```python
# Extract all possible null terminated strings passed in as the first argument.
strings = []
for context in emulator.iter_context_at(addr, depth=1):
    # mov     eax, [ebp+arg_0]
    strings.append(context.memory.read_data(context.operands[1].value))
    
# Extract the function arguments for a call, but add depth of 1 to account for a possible wrapper.
context = emulator.context_at(addr, depth=1)
```

### Emulating function calls

We can emulate the function call instructions found during emulation by setting the 
`call_depth` option to the number of call levels deep you would like it to emulate.
When set, a call instruction will cause the emulator to step into the referenced function
and emulate the instructions as if it was executed normally. 
WARNING: This could cause a significant performance hit depending on the function.
By default, this is set to 0, meaning call instructions will not be emulated unless there is a call hook.

```python
context = emulator.context_at(addr, call_depth=3)  # allows 3 levels deep of calls.
```

If you would like to emulate a specific function or call instruction we can instead
create a call hook using `emulate_call()` described in [Emulating Subroutines](#emulating-subroutines).
This also can accept a `call_depth` option if desired.


## Emulating Loops

By default, when a context, operand, or function argument is requested, the emulator
forces itself down a path of basic blocks and emulates each block only once, ignoring
any loops. This is fine for most cases when all we care about is retrieving
a stack string. However, if we would like to ensure some type of inline routine
is successfully run we can enable the `follow_loops` flag on any of the following
functions: `context_at()`, `iter_context_at()`, `get_function_args()`, `iter_function_args()`, `get_operand_value()`, `iter_operand_value()`

```python
context = emulator.context_at(addr, follow_loops=True)
```

When `follow_loops` is enabled, the `exhaustive` flag takes on a new meaning.
If `exhaustive` is also enabled, the emulator follows loops for all call stack levels.
If `exhaustive` is disabled, only call stack level 0 follows loops. 

WARNING: When emulating loops, there is a chance that the desired end instruction
never gets reached due to an infinite loop.
Therefore, there is a limit on the maximum number of instructions allowed before raising a RuntimeError.
This number is adjustable when initializing the emulator.

```python
import dragodis
import rugosa


with dragodis.open_program(r"C:\input.ext") as dis:
    emulator = rugosa.Emulator(dis, max_instructions=10000)
```



## Retrieving Function Arguments

The function arguments within a CPU context can be retrieved and set for any `call` instruction,
or for the passed in arguments of the current subroutine that is being traced.

Use the `get_function_args()` function or `.function_args` property to retrieve the current arguments relative to the given
function. Then use the returned objects to retrieve and set the name, type, and value of the argument. As well, the memory address can also be retrieved for stack arguments.

```python
import dragodis
import rugosa


with dragodis.open_program(r"C:\input.exe") as dis:
   emulator = rugosa.Emulator(dis)
   
   call_ea = 0x401049
   context = emulator.context_at(call_ea)
   
   args = context.get_function_args(call_ea)  # for arguments for given call instruction address.
   # OR
   args = context.function_args  # for arguments at current call instruction context is pointing at.
   
   print(args[0].name)
   print(args[0].type)
   print(args[0].value)
   print(args[0].declaration)
   
   # Set the value to something new.
   args[0].value = 0xff
```

As a shortcut, the function arguments for the subroutine currently being traced can be retrieved
using `passed_in_args`.

This can be useful for allocating the arguments before tracing.

```python
import dragodis
import rugosa


with dragodis.open_program(r"C:\input.exe") as dis:
   emulator = rugosa.Emulator(dis)
   
   func_start = 0x401000
   call_ea = 0x401049
   
   # Create a context with passed in argument allocated before tracing.
   context = emulator.new_context()
   context.ip = func_start
   args = context.passed_in_args
   ptr = context.memory.alloc(10)
   context.memory.write(ptr, b"custom data")
   args[0].value = ptr
   
   # Pull a new context with instructions emulated up to call_ea (not following loops)
   context = emulator.context_at(call_ea, init_context=context)
   print(context.passed_in_args[0].value)
```



## Modifying Function Signature

When extracting function arguments, if the disassembler did not correctly determine the number of arguments, we
can adjust the function signature beforehand through a variety of methods:

```python
import dragodis
import rugosa


with dragodis.open_program(r"C:\input.ext") as dis:
   emulator = rugosa.Emulator(dis)
   
   call_ea = 0x401049
   
   # Disassembler incorrectly determines the number of arguments, we need to modify the function signature.
   context = emulator.context_at(call_ea)
   args = context.function_args  # len(args) == 1
```
    
1. Force a specific number of arguments using the `num_args` parameter on `*_function_args()` type functions.
    - This forces any extra arguments that the disassembler doesn't detect as an "int" type.
    - This does not affect the function type within the IDB file.
    
    ```python
    args = context.get_function_args(num_args=2)  # len(args) == 2
    ```
    
2. Use `get_function_signature()` on the context to retreive a `FunctionSignature` object that allows for modifying
    the function signature before argument extraction.
    - The `FunctionSignature` object also allows for querying each function type, getting their size, and modifying in-place.
    
    ```python
    func_sig = context.get_function_signature()
    func_sig.add_argument("char")
    func_sig.remove_argument(0)
    func_sig.insert_argument(1, "_BYTE *")

    for arg in func_sig.args:
       print("Name: ", arg.name)   
       print("Type: ", arg.type)
       print("Size: ", arg.width)
       print("Value: ", arg.value)
              
       # We can also modify types before extraction to adjust the value that gets returned.
       if arg.idx == 1:
           arg.type = "DWORD"
                     
    args = [arg.value for arg in func_sig.args]  # len(args) == 2
    ```


## Emulating Subroutines

`function_tracing` can statically emulate a full subroutine within the dissasembler as if it was a
Python function through the use of the `create_emulated()` function. 
This function accepts an address within a subroutine and returns a Python
function that emulates the subroutine when executed.

The emulated function accepts the same number of positional arguments as detected by the disassembler
and returns the rax register.

The emulated function can also accept a `ProcessorContext` as the keyword argument `context`.
This can be used to allow for modifying the context beforehand or retrieving values afterwards.

```python
import dragodis
import rugosa


with dragodis.open_program(r"C:\input.exe") as dis:   
   emulator = rugosa.Emulator(dis)
   
   # Emulate the XOR decryption function at 0x401000 of the executable.
   xor_decrypt = emulator.create_emulated(0x401000)
   
   # Create a context that we can fill with our encrypted data before emulating.
   context = emulator.new_context()
   
   # First argument holds a pointer to the encrypted string which gets decrypted in-place.
   enc_data = b"Idmmn!Vnsme "
   key = 1
   ptr = context.memory.alloc(len(enc_data))
   context.memory.write(ptr, enc_data)
   # Pass in arguments and context to fill.
   xor_decrypt(ptr, key, context=context)
   
   print(context.memory.read_data(ptr))
   # b"Hello World!"
```

The `create_emulated()` function can also accept `return_type` or `return_size` keyword arguments
to define how to handle the returned pointer. 
This may help to avoid needing to pass in a context beforehand if only the return value is important.

```python
import dragodis
import rugosa
from rugosa.emulation import constants


with dragodis.open_program(r"C:\input.exe") as dis:   
   emulator = rugosa.Emulator(dis)
   
   # Emulate the XOR decryption function at 0x401000 of the executable.
   # The xor decryption function returns a pointer to the decrypted string.
   xor_decrypt = emulator.create_emulated(0x401000, return_type=constants.STRING)
   
   print(xor_decrypt(b"Idmmn!Vnsme ", 1))
   # b'Hello World!'
```

By default, the number of positional arguments passed into the emulated function does not matter. 
If too few arguments are provided, the remaining arguments are pulled from the context based on the calling convention of the emulated function. 
If more arguments than required are provided, they will be ignored. 
However, if the `enforce_args` keyword argument is set to True, a `TypeError` will be raised.  

```python
import dragodis
import rugosa


with dragodis.open_program(r"C:\input.exe") as dis:   
   emulator = rugosa.Emulator(dis)

   xor_decrypt = emulator.create_emulated(0x401000)
   
   xor_decrypt(b"Idmmn!Vnsme ")
   # Success: Assumes key of 0.
   xor_decrypt(b"Idmmn!Vnsme ", context=ctx)
   # Success: Pulls key from stack in ctx.
   
   xor_decrypt = emulator.create_emulated(0x401000, enforce_args=True)
   
   xor_decrypt(b"Idmmn!Vnsme ")
   # TypeError: Function takes 2 positional arguments, but 1 were given.
```

A subroutine can also hook to function calls as described in [Hook Emulated Functions](#hook-emulated-functions).


## Hooking Functions

Rugosa emulates the calls to a few common C/C++ library functions (`memmove`, `memcpy`, `strcpy`, etc) to help ensure data moves get emulated correctly. These can be found in [call_hooks](../rugosa/emulation/call_hooks).

You can also provide your own hooked functions to emulate results and/or report information
for calls to a specific function. To hook a function, call the `hook_call()` function on
the `Emulator`. 

The hook function accepts 2 parameters:

1. The name or starting address of the function to hook.
2. A Python function to be called to emulate the function. This function must accept 3 parameters: the current cpu context, the function name, and the passed in function arguments. This function should then return an appropriate return value that will be then set to the `eax` register or `None` if the register should not be changed.
   
    
```python
import base64
import dragodis
import rugosa


with dragodis.open_program(r"C:\input.exe") as dis:   
   emulator = rugosa.Emulator(dis)

   # Using function hooking to emulate a base64 algorithm and collect results for reporting.
   decoded_strings = []
   def func_hook(context, func_name, func_args):
       global decoded_strings
       logger.info("{} was called with: {!r}".format(func_name, func_args))
       # Base64 decode passed in string and then set it to destination pointer.
       src_ptr, src_size, dst_ptr = func_args
       
       src = context.memory.read(src_ptr, src_size)
       try:
           dst = base64.b64decode(src)
       except TypeError:
           return -1  # emulate error result
       context.memory.write(dst_ptr, dst)
           
       # report string for our own purposes
       decoded_strings.append(dst)
           
       # emulate returned results
       return len(dst)
   
   emulator.hook_call("Base64Decode", func_hook)  # function start_ea can also be used instead of a name
```

### Hook Emulated Functions

Fully emulated functions that you would get from `create_emulated()` can also hook to a function call by calling the `emulate_call()` function with the function start address or name.

```python
import dragodis
import rugosa


with dragodis.open_program(r"C:\input.exe") as dis:   
   emulator = rugosa.Emulator(dis)
   
   xor_func_ea = 0x401000
   emulator.emulate_call(xor_func_ea)
   
   # Now all calls to the xor function will be emulated when retrieving a context.
```


## Hooking Instructions

Callback functions can be executed before or after an instruction is emulated through the use of the
`hook_instruction()` function of the `Emulator` object.

```python
import dragodis
import rugosa


with dragodis.open_program(r"C:\input.exe") as dis:   
   emulator = rugosa.Emulator(dis)

   pushes = []
   def push_hook(context, instruction):
       pushes.append(instruction.operands[0].value)
   
   
   # Hook instructions with "push" opcode to be run before instruction is emulated.
   # pre boolean is used to determine if the hook should run before or after the instruction is emulated.
   emulator.hook_instruction("push", push_hook, pre=True) 
```


## Hooking Opcodes

The implementation for emulating a specific instruction opcode can be replaced or added
through the use of the `hook_opcode()` function of the `Emulator` object.

This will allow providing a custom implementation or add missing opcodes.

For postfixed based architectures like ARM, setting the base opcode will replace the implementations
for all variants of the opcode.
(e.g. setting `ldr` will hook `ldreq`, `ldrsh`, etc.)

```python
import dragodis
import rugosa


with dragodis.open_program(r"C:\input.exe") as dis:   
   emulator = rugosa.Emulator(dis)


   def push(context, instruction):
       """Implements emulation of a "push" instruction."""
       operand = instruction.operands[0]
       context.sp -= context.byteness
       value_bytes = operand.value.to_bytes(operand.width, "little")
       context.memory.write(context.sp, value_bytes)
   
   # Hook "push" instruction emulation to use our custom implementation (replacing the builtin one)
   emulator.hook_opcode("push", push)
```

*WARNING: As opposed to `hook_instruction()`, this will completely replace any existing implementation for that opcode. As well, only one hook can be provided for each opcode.*



## Pointer History

You can retrieve the history of a pointer across multiple memory copy routines using the `get_pointer_history()`
function on the `ProcessorContext` object. This function returns a list of all previous
pointer locations sorted from earliest to latest.

```python
history = context.get_pointer_history(addr)
for ip, ea in reversed(history):
    print("0x{:x} :: 0x{:x} -> 0x{:x}".format(ea, addr))
    addr = ea
```


## Variables

As emulation occurs, stack and global variables are recorded in the cpu context which
can then be extracted by the user.

You can view variables that have been encountered during emulation using the `variables` attribute on the context.

```python
# show all encountered variables
print(context.variables.names)
print(context.variables.addrs)

# iterate all the variables encountered during emulation
for var in context.variables:
    print(f"name = {var.name}")    # name of variable
    print(f"address = {var.addr}")     # address of variable as found in context memory.
    print(f"location = {'stack' if var.is_stack else 'global'}")  # stack vs global variable
    print(f"size = {var.size}")    # size of data variable is pointing to.
    print(f"data = {var.data}")    # dereferenced raw data
    print(f"type = {var.data_type}")  # the data type of the variable
    print(f"value = {var.value}")  # dereferenced variable unpacked based on data type
    print(f"references = {sorted(var.references)}")   # instruction addresses that reference this variable
    
    # Variable values can also be set.
    if var.data_type == 'dword':
        var.value = 21    


# variables can also be queried just like a dictionary by either name or address
if "arg_0" in context.variables:
    print(context.variables["arg_0"])

var = context.variables.get(context.sp + 8, None)
if var:
    print(var)
```


## Objects

As emulation occurs, some high level objects are recorded in the cpu context which can then be 
extracted by the user.

Currently files and registry keys are supported.

```python
from rugosa.emulation import objects

print(context.objects)  # Returns ObjectMap class that can be iterated for all instantiated objects.

for obj in context.objects:
    if isinstance(obj, objects.File):
        print(obj.name)
    elif isinstance(obj, objects.RegKey):
        print(obj.sub_key)

# context.files, context.reg_keys, or context.services can also be used for filtering.
print(context.files)
print(context.reg_keys)
print(context.services)

# Files in particular can be used to write out files.
# Obviously, be careful with this!
for file in context.files:
    if file.data:
        with open(file.name, "wb") as fo:
           fo.write(file.data)
```


## Actions

As emulation occurs, interesting actions such as registry, file or process activity will be recorded
in the `actions` attribute. A full list of supported actions can be found in 
[rugosa.emulation.actions](../rugosa/emulation/actions.py)

```python
from rugosa.emulation import actions

print(context.actions)

for action in context.actions:
    if isinstance(action, actions.CommandExecuted):
        print(f"Executed {action.command} at address {hex(action.ip)}")
```


## Memory Streaming

The emulated memory object can open a file-like stream object using the `.open()` function.
This will allow you to pass in the emulated memory wherever a file-like stream is expected.

To open a stream starting at a specific address, provide the address in the `.open(address)` function.

Just calling `.open()` without any arguments will cause the memory stream to be opened starting at the
base address of the first allocated block.

```python
with context.memory.open(0x401000) as stream:
    print(stream.tell_address())  # current seek location as virtual address: 0x401000
    print(stream.tell())   # current seek location relative to starting address: 0
    print(stream.read(10))
    stream.seek_address(0x401234)   # seek to a specific address
    stream.seek(100)  # 100 bytes from start address
    stream.write(b"hello")  # writes data back to emulated memory at current seek location.
```
