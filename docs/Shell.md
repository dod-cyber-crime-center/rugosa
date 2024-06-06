# CLI Shell Tool

Rugosa includes an interactive shell tool created with [cmd2](https://cmd2.readthedocs.io) for emulating and traversing 
a given binary.

- [Usage](#usage)
- [Disassembly](#disassembly)
- [Emulation Control](#emulation-control)
- [Emulation Artifacts](#emulation-artifacts)
- [Emulation Info](#emulation-info)
- [Extras](#extras)
  - [Startup Commands](#startup-commands)
  - [Settings](#settings)
  - [Shelling into a Python Interpreter](#shelling-into-a-python-interpreter)
  - [Target Variables](#target-variables)


## Usage

The shell tool can be started using the `rugosa` command followed by the path to the binary file to analyze.

This will open a new shell with the current emulation context pointing to the entry point of the binary.

```console
$ rugosa binary.exe
 ____                              
|  _ \ _   _  __ _  ___  ___  __ _ 
| |_) | | | |/ _` |/ _ \/ __|/ _` |
|  _ <| |_| | (_| | (_) \__ \ (_| |
|_| \_\\__,_|\__, |\___/|___/\__,_|
             |___/                  v0.11.0

Department of Defense Cyber Crime Center (DC3)

------------  ---------------------------------
File          /home/ubuntu/dev/data/binary.exe
Disassembler  IDA
Processor     x86
Compiler      Visual C++
Bit size      32
Endianness    LE
Entry Point   0x004014e0
------------  ---------------------------------
(0x004014e0)>
```

By default, rugosa will use the backend disassembler set by [dragodis](https://github.com/dod-cyber-crime-center/Dragodis) 
which is determined by the `DRAGODIS_DISASSEMBLER` environment variable.
The disassembler can also be provided within the command line using the `--backend` flag.

Please ensure the disassembler used is first setup by following the [instructions](https://github.com/dod-cyber-crime-center/Dragodis/blob/master/docs/install.md) provided by dragodis.

```console
rugosa binary.exe --backend ghidra
```

After startup a number of different commands defined below can be used to view the disassembly and traverse emulation.
Once finished the `quit` or `exit` command will exit the shell.

## Disassembly

The following commands are used to display information about the disassembled binary.

### `code` command

Prints the decompiled code of the current function.

```console
(0x00401150)> code
int __cdecl main(int argc, const char **argv, const char **envp)
{
  sub_401030();
  sub_4012A0("%s\n", aIdmmnVnsme);
  sub_4012A0("%s\n", aVgqvQvpkleUkvj);
  sub_4012A0("%s\n", aWkfRvjHAqltmEl);
  sub_4012A0("%s\n", aKeoMwWpvkjcEjE);
  sub_4012A0("%s\n", aDflaGpwkvMjiVL);
  sub_4012A0("%s\n", aEgruGhbBiauCge);
  sub_4012A0("%s\n", aCv3gV3pargv3qf);
  sub_4012A0("%s\n", aC);
  sub_4012A0("%s\n", asc_40C114);
  sub_4012A0("%s\n", aQfbwfsqlFppb);
  sub_4012A0("%s\n", aTsudfs);
  sub_4012A0("%s\n", byte_40C138);
  sub_4012A0("%s\n", a5VTr4vTrv4tV);
  sub_4012A0("%s\n", aAkjdgbaKjgdbjk);
  sub_4012A0("%s\n", asc_40C174);
  sub_4012A0("%s\n", a4);
  sub_4012A0("%s\n", asc_40C1C4);
  sub_4012A0("%s\n", aLmfoghknlmgfoh);
  return 0;
}
```

An address or [target variable](#target-variables) can be provided to print the code of another function.

```console
(0x00401150)> code sub_401030
int sub_401030()
{
  sub_401000(aIdmmnVnsme, 1);
  sub_401000(aVgqvQvpkleUkvj, 2);
  sub_401000(aWkfRvjHAqltmEl, 3);
  sub_401000(aKeoMwWpvkjcEjE, 4);
  sub_401000(aDflaGpwkvMjiVL, 5);
  sub_401000(aEgruGhbBiauCge, 6);
  sub_401000(aCv3gV3pargv3qf, 19);
  sub_401000(aC, 23);
  sub_401000(asc_40C114, 26);
  sub_401000(aQfbwfsqlFppb, 35);
  sub_401000(aTsudfs, 39);
  sub_401000(byte_40C138, 64);
  sub_401000(a5VTr4vTrv4tV, 70);
  sub_401000(aAkjdgbaKjgdbjk, 115);
  sub_401000(asc_40C174, 117);
  sub_401000(a4, 119);
  sub_401000(asc_40C1C4, 122);
  return sub_401000(aLmfoghknlmgfoh, 127);
}
```

### `exports` command

Lists the export symbols within the binary.

```console
(0x00401150)> exports
address     name      num_references
----------  ------  ----------------
0x004014e0  start                  0
```

### `functions` command

Lists the functions of the binary.

```console
(0x00401150)> functions
start       end         name
----------  ----------  ----------------------------
0x00401030  0x00401143  sub_401030
0x00401150  0x004012a0  _main
0x00401365  0x0040138a  _fast_error_exit
0x0040138e  0x004014e0  ___tmainCRTStartup
0x004014e0  0x004014ea  start
0x0040261c  0x00402661  __SEH_prolog4
0x00402661  0x00402675  __SEH_epilog4
0x00402680  0x0040280c  SEH_405330
...
```

*Aliases: `func`, `funcs`, `function`*

#### `create` subcommand

The `create` subcommand can be used to attempt to define a new function
when the disassembler has failed to discover it.

Under the hood, this is using the `rugosa.func_utils.create_function()` utility to attempt to discover
function boundaries surrounding a given address and define it as a function.

```console
(0x004014e0)> goto 0x40116f
Function doesn't exist at 0x0040116f
(0x004014e0)> functions create 0x40116f
Function created: _main @ 0x00401150
(0x004014e0)> goto 0x40116f
(0x0040116f)> 
```

### `imports` command

Prints the import symbols within the binary.

```console
(0x0040116f)> imports
address     thunk_address    name                                   namespace      num_references    num_calls
----------  ---------------  -------------------------------------  -----------  ----------------  -----------
0x0040a000                   GetCommandLineA                        KERNEL32                    3            1
0x0040a004                   EnterCriticalSection                   KERNEL32                    8            4
0x0040a008                   LeaveCriticalSection                   KERNEL32                    8            4
0x0040a00c                   TerminateProcess                       KERNEL32                    4            2
0x0040a010                   GetCurrentProcess                      KERNEL32                    4            2
0x0040a014                   UnhandledExceptionFilter               KERNEL32                    6            3
0x0040a018                   SetUnhandledExceptionFilter            KERNEL32                    8            4
0x0040a01c                   IsDebuggerPresent                      KERNEL32                    4            2
0x0040a020                   GetModuleHandleW                       KERNEL32                   12            6
0x0040a024                   Sleep                                  KERNEL32                    8            4
0x0040a028                   GetProcAddress                         KERNEL32                   20           14
0x0040a02c                   ExitProcess                            KERNEL32                    2            1
0x0040a030                   WriteFile                              KERNEL32                   14            7
0x0040a034                   GetStdHandle                           KERNEL32                    4            2
0x0040a038                   GetModuleFileNameA                     KERNEL32                    4            2
0x0040a03c                   FreeEnvironmentStringsA                KERNEL32                    4            2
0x0040a040                   GetEnvironmentStrings                  KERNEL32                    2            1
0x0040a044                   FreeEnvironmentStringsW                KERNEL32                    2            1
...
```

### `info` command

Prints information about the given address/[target variable](#target-variables) or the current instruction of the program counter.

```console
(0x004028cf)> info 0x40a028
---------------  -----------------------------------
Name             GetProcAddress
Address          0x0040a028
Size             4
Location         .idata: 0x0040a000 --> 0x0040a110
Function
Type             dword
Value            0xffffffff
References To    20
References From  0
Import           KERNEL32/GetProcAddress: 0x0040a028
Export
Registers
Operands         0: ds:GetProcAddress
Variables
---------------  -----------------------------------
```

*Aliases: `i`, `what`*

### `instruction` command

Prints the instruction for a given address/[target variable](#target-variables) or the current instruction of the program counter.

```console
(0x0040148f)> instruction
cmp     dword ptr [ebp-1Ch], 0
(0x0040148f)> instruction 0x401158
push    offset aIdmmnVnsme; "Idmmn!Vnsme "
```

---
**TIP**

To have the current instruction always displayed in the prompt, set the `display_instruction` setting.

```console
(0x0040148f)> set display_instruction True
display_instruction - was: False
now: True
(0x0040148f: cmp     dword ptr [ebp-1Ch], 0)>
```

---

*Aliases: `insn`*

### `references` command

Prints the references to/from the given address or [target variable](#target-variables).

**Args:**

- `-i`/`--include-instruction` will enable instruction/data text to be displayed.
- `-d`/`--direction` will set the direction of references to include. (defaults to both directions)


```console
(0x00401150)> references GetProcAddress -i
direction    type       from_address    from_text                       to_address       to_text
-----------  ---------  --------------  ------------------------------  ------------  ----------
to           code_call  0x004028cf      call    ds:GetProcAddress       0x0040a028    4294967295
to           code_call  0x0040363d      call    ds:GetProcAddress       0x0040a028    4294967295
to           code_call  0x004036b8      call    ds:GetProcAddress       0x0040a028    4294967295
to           code_call  0x00403790      call    ebx ; GetProcAddress    0x0040a028    4294967295
to           code_call  0x004037a0      call    ebx ; GetProcAddress    0x0040a028    4294967295
to           code_call  0x00403a24      call    esi ; GetProcAddress    0x0040a028    4294967295
to           code_call  0x00403a31      call    esi ; GetProcAddress    0x0040a028    4294967295
to           code_call  0x00403a3e      call    esi ; GetProcAddress    0x0040a028    4294967295
to           code_call  0x00403a4b      call    esi ; GetProcAddress    0x0040a028    4294967295
to           code_call  0x0040588f      call    esi ; GetProcAddress    0x0040a028    4294967295
to           code_call  0x004058ac      call    esi ; GetProcAddress    0x0040a028    4294967295
to           code_call  0x004058c1      call    esi ; GetProcAddress    0x0040a028    4294967295
to           code_call  0x004058d6      call    esi ; GetProcAddress    0x0040a028    4294967295
to           code_call  0x004058ee      call    esi ; GetProcAddress    0x0040a028    4294967295
to           data_read  0x004028cf      call    ds:GetProcAddress       0x0040a028    4294967295
to           data_read  0x0040363d      call    ds:GetProcAddress       0x0040a028    4294967295
to           data_read  0x004036b8      call    ds:GetProcAddress       0x0040a028    4294967295
to           data_read  0x0040378a      mov     ebx, ds:GetProcAddress  0x0040a028    4294967295
to           data_read  0x00403a18      mov     esi, ds:GetProcAddress  0x0040a028    4294967295
to           data_read  0x00405883      mov     esi, ds:GetProcAddress  0x0040a028    4294967295
```

*Aliases: `ref`, `refs`*

### `search` command

Searches disassembly for given regex pattern.
Lists the first disassembly line containing the matched data along with the matched data itself.

**Args:**
- `-s`/`--segment` restricts search to a given segment.
- `-n`/`--num` limits results to given number. (defaults to all results)

```console
(0x004014e0)> search \x68.{4}\xe8.\x00\x00\x00
segment    address     text                          function    data
---------  ----------  ----------------------------  ----------  -------------------------------------
.text      0x004011a5  push    offset aS_3; "%s\n"   _main       b'hX\xc2@\x00\xe8\xf1\x00\x00\x00'
.text      0x004011b7  push    offset aS_4; "%s\n"   _main       b'h\\\xc2@\x00\xe8\xdf\x00\x00\x00'
.text      0x004011c9  push    offset aS_5; "%s\n"   _main       b'h`\xc2@\x00\xe8\xcd\x00\x00\x00'
.text      0x004011db  push    offset aS_6; "%s\n"   _main       b'hd\xc2@\x00\xe8\xbb\x00\x00\x00'
.text      0x004011ed  push    offset aS_7; "%s\n"   _main       b'hh\xc2@\x00\xe8\xa9\x00\x00\x00'
.text      0x004011ff  push    offset aS_8; "%s\n"   _main       b'hl\xc2@\x00\xe8\x97\x00\x00\x00'
.text      0x00401211  push    offset aS_9; "%s\n"   _main       b'hp\xc2@\x00\xe8\x85\x00\x00\x00'
.text      0x00401223  push    offset aS_10; "%s\n"  _main       b'ht\xc2@\x00\xe8s\x00\x00\x00'
.text      0x00401235  push    offset aS_11; "%s\n"  _main       b'hx\xc2@\x00\xe8a\x00\x00\x00'
.text      0x00401247  push    offset aS_12; "%s\n"  _main       b'h|\xc2@\x00\xe8O\x00\x00\x00'
.text      0x00401259  push    offset aS_13; "%s\n"  _main       b'h\x80\xc2@\x00\xe8=\x00\x00\x00'
.text      0x0040126b  push    offset aS_14; "%s\n"  _main       b'h\x84\xc2@\x00\xe8+\x00\x00\x00'
.text      0x0040127d  push    offset aS_15; "%s\n"  _main       b'h\x88\xc2@\x00\xe8\x19\x00\x00\x00'
.text      0x0040128f  push    offset aS_16; "%s\n"  _main       b'h\x8c\xc2@\x00\xe8\x07\x00\x00\x00'
```

### `segments` command

Lists the segments within the binary.

```console
(0x004014e0)> segments
start       end           size  name    permissions      bit_size  initialized
----------  ----------  ------  ------  -------------  ----------  -------------
0x00401000  0x0040a000   36864  .text   EXECUTE|READ           32  True
0x0040a000  0x0040a110     272  .idata  READ                   32  False
0x0040a110  0x0040c000    7920  .rdata  READ                   32  True
0x0040c000  0x0040f000   12288  .data   WRITE|READ             32  True
```

*Aliases: `seg`*

### `stack` command

Lists the stack variables within the current function.

```console
(0x00401150)> stack
offset      size  data_type      name
--------  ------  -------------  ------
0x4            4  int            argc
0x8            4  const char **  argv
0xc            4  const char **  envp
```

### `status` command

Lists general information about the binary being analyzed.

```console
(0x00401150)> status
------------  ---------------------------------
File          /home/ubuntu/dev/data/binary.exe
Disassembler  IDA
Processor     x86
Compiler      Visual C++
Bit size      32
Endianness    LE
Entry Point   0x004014e0
------------  ---------------------------------
```

### `strings` command

Lists the discovered strings within the binary.

**Args:**
- `--min` sets the minimum length for a valid string. (defaults to 3)
- `--raw` writes out string data as raw binary when given an address or [target variable](#target-variables).

```console
(0x00401150)> strings
address       size  string
----------  ------  -----------------------------------------------------------------------------------------------------------------------------------------------------------------
0x0040a150       6  (null)
0x0040a160       6  (null)
0x0040a179       3  EEE
0x0040a189       7  ( 8PX
0x0040a191       6  700WP
0x0040a199       3  
0x0040a1a0       7 `h````
0x0040a1a9       9  xpxxxx
0x0040a1b6       3  
0x0040a1c4      14  CorExitProcess
0x0040a1d4      11  mscoree.dll
0x0040a1ec      14  runtime error
0x0040a200      13  TLOSS error
0x0040a210      12  SING error
0x0040a220      14  DOMAIN error
0x0040a230     154  R6034
                    An application has made an attempt to load the C runtime library incorrectly.
                    Please contact the application's support team for more information.
0x0040a2d0     246  R6033
                    - Attempt to use MSIL code from this assembly during native code initialization
                    This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native constructor or from DllMain.
0x0040a3c8      50  R6032
                    - not enough space for locale information
0x0040a400      98  R6031
                    - Attempt to initialize the CRT more than once.
                    This indicates a bug in your application.
0x0040a464      30  R6030
                    - CRT not initialized
...
```

An address or [target variable](#target-variables) can be provided to extract the string at a specific location.
Combined with `--raw`, we can provide the raw data for output redirection or pipelining.

```console
(0x00401150)> strings 0x40c000 --raw | hexdump -C
00000000  49 64 6d 6d 6e 21 56 6e  73 6d 65 20              |Idmmn!Vnsme |
0000000c
```

## Emulation Control

The following commands are used to control emulation.

### `goto` command

Sets execution context to the given address or [target variable](#target-variables). 
By default, this will cause rugosa to trace a path down from the beginning of the current function to the
requested address and then emulate those instructions. The determined branch path can be viewed with the [branch_history](#branch_history-command)
command and an alternative path can be selected using the [alternative](#alternative-command) command.

**Args:**
- `-k`/`--keep` determines whether to emulate using the currently set context. By default a new context is created.
- `-d`/`--depth` sets the number of calls up the stack to emulate first before starting the current function. (defaults to 0)
- `-c`/`--call-depth` sets the number of function calls deep within the current function we are allowed to emulate. (defaults to not emulating any function calls except hooked ones)
- `-f`/`--follow-loops` determines if loops will be followed during emulation. Otherwise, only direct pathing is used.

```console
(0x1400015e0)> goto 0x14000173d
(0x14000173d)>
```

*Aliases: `g`*

### `next` command

Executes the next instruction(s).
A count can be provided to emulate multiple instructions.

**Args:**
- `-c`/`--call-depth` sets the number of function calls deep within the current function we are allowed to emulate. (defaults to not emulating any function calls except hooked ones)

```console
(0x00401477)> next
(0x00401478)> next 5
(0x0040148f)> 
```

*Aliases: `n`*

### `continue` command

Executes instructions until we hit the given address/[target variable](#target-variables) or we reach a function
return (which ever comes first).

**Args:**
- `-c`/`--call-depth` sets the number of function calls deep within the current function we are allowed to emulate. (defaults to not emulating any function calls except hooked ones)

```console
(0x1400015e0)> dis
0x1400015e0: __int64 __fastcall main();
 -> 0x1400015e0: push    rbp
    0x1400015e1: push    rbx
    0x1400015e2: sub     rsp, 68h
    0x1400015e6: lea     rbp, [rsp+60h]
    0x1400015eb: call    __main
    0x1400015f0: lea     rax, aThisIsSomeSamp; "This is some sample data to write to th"...
    0x1400015f7: mov     [rbp+10h+data], rax
    0x1400015fb: mov     [rsp+70h+hTemplateFile], 0; hTemplateFile
    0x140001604: mov     [rsp+70h+dwFlagsAndAttributes], 80h; dwFlagsAndAttributes
    0x14000160c: mov     [rsp+70h+dwCreationDisposition], 2; dwCreationDisposition
    ...
(0x1400015e0)> continue 
(0x140001783)> dis
0x1400015e0: __int64 __fastcall main();
    ...
    0x140001763: call    _ZNSolsEPFRSoS_E; std::ostream::operator<<(std::ostream & (*)(std::ostream &))
    0x140001768: mov     rax, [rbp+10h+hFile]
    0x14000176c: mov     rcx, rax; _QWORD
    0x14000176f: mov     rax, cs:__IAT_start__
    0x140001776: call    rax ; __IAT_start__
    0x140001778: mov     eax, 0
    0x14000177d: add     rsp, 68h
    0x140001781: pop     rbx
    0x140001782: pop     rbp
 -> 0x140001783: retn
    0x1400016f5: lea     rax, aErrorWritingTo; "Error writing to file: "
    0x1400016fc: mov     rdx, rax; a2
    0x1400016ff: mov     rax, cs:_refptr__ZSt4cout
    0x140001706: mov     rcx, rax; a1
    0x140001709: call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc; std::operator<<<std::char_traits<char>>(std::ostream &,char const*)
    0x14000170e: mov     rbx, rax
    0x140001711: mov     rax, cs:__imp_GetLastError
    0x140001718: call    rax ; __imp_GetLastError
    0x14000171a: mov     edx, eax; a2
    ...
```

A given address or [target variable](#target-variables) can be provided to cause emulation to stop if the address 
is seen.

```console
(0x140001783)> goto main
(0x1400015e0)> continue 0x14000173d
(0x14000173d)> dis
0x1400015e0: __int64 __fastcall main();
    ...
    0x1400016d4: mov     qword ptr [rsp+70h+dwCreationDisposition], 0; lpOverlapped
    0x1400016dd: mov     r9, rcx; lpNumberOfBytesWritten
    0x1400016e0: mov     rcx, rax; hFile
    0x1400016e3: mov     rax, cs:__imp_WriteFile
    0x1400016ea: call    rax ; __imp_WriteFile
    0x1400016ec: test    eax, eax
    0x1400016ee: setz    al
    0x1400016f1: test    al, al
    0x1400016f3: jz      short loc_14000173D
 -> 0x14000173d: lea     rax, aFileWroteSucce; "File wrote successfully."
    0x140001744: mov     rdx, rax; a2
    0x140001747: mov     rax, cs:_refptr__ZSt4cout
    0x14000174e: mov     rcx, rax; a1
    0x140001751: call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc; std::operator<<<std::char_traits<char>>(std::ostream &,char const*)
    0x140001756: mov     rcx, rax; a1
    0x140001759: mov     rax, cs:_refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_
    0x140001760: mov     rdx, rax; a2
    0x140001763: call    _ZNSolsEPFRSoS_E; std::ostream::operator<<(std::ostream & (*)(std::ostream &))
    0x140001768: mov     rax, [rbp+10h+hFile]
    ...
```

This can also be used to provide an instruction opcode to stop at as well.

```console
(0x004014e0)> g sub_401000 
(0x00401000)> dis
0x00401000: _BYTE *__cdecl sub_401000(_BYTE *a1, char a2);
 -> 0x00401000: push    ebp
    0x00401001: mov     ebp, esp
    0x00401003: mov     eax, [ebp+a1]
    0x00401006: movsx   ecx, byte ptr [eax]
    0x00401009: test    ecx, ecx
    0x0040100b: jz      short loc_401029
    0x0040100d: movsx   edx, [ebp+a2]
    0x00401011: mov     eax, [ebp+a1]
    0x00401014: movsx   ecx, byte ptr [eax]
    0x00401017: xor     ecx, edx
    ...
(0x00401000)> c movsx
(0x00401006)> dis
0x00401000: _BYTE *__cdecl sub_401000(_BYTE *a1, char a2);
    0x00401000: push    ebp
    0x00401001: mov     ebp, esp
    0x00401003: mov     eax, [ebp+a1]
 -> 0x00401006: movsx   ecx, byte ptr [eax]
    0x00401009: test    ecx, ecx
    0x0040100b: jz      short loc_401029
    0x0040100d: movsx   edx, [ebp+a2]
    0x00401011: mov     eax, [ebp+a1]
    0x00401014: movsx   ecx, byte ptr [eax]
    0x00401017: xor     ecx, edx
    0x00401019: mov     edx, [ebp+a1]
    0x0040101c: mov     [edx], cl
    0x0040101e: mov     eax, [ebp+a1]
    ...
```


*Aliases: `c`*

### `alternative` command

Sets the execution context to use an alternative branching path to reach the same destination.
Prints the difference in branch pathing (displaying the first address of each basic block).

*"forced" means the branching from the previous block was forced even though the emulated opcodes would not have dictated 
that direction.*

```console
(0x1400016bd)> goto 0x140001783
(0x140001783)> exec_history -i > first_path.txt
(0x140001783)> alternative
Branch Path:
  0x1400015e0 
+ 0x14000168e 
- 0x140001643 (forced)
+ 0x1400016f5 (forced)
  0x14000177d 
(0x140001783)> alternative
Branch Path:
  0x1400015e0 
  0x14000168e 
- 0x1400016f5 (forced)
+ 0x14000173d 
(0x140001783)> exec_history -i | diff first_path.txt -
23,39c23,61
< 0x140001643  lea     rax, a2; "Error creating file: "
< 0x14000164a  mov     rdx, rax; a2
< 0x14000164d  mov     rax, cs:_refptr__ZSt4cerr
< 0x140001654  mov     rcx, rax; a1
< 0x140001657  call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc; std::operator<<<std::char_traits<char>>(std::ostream &,char const*)
< 0x14000165c  mov     rbx, rax
< 0x14000165f  mov     rax, cs:__imp_GetLastError
< 0x140001666  call    rax ; __imp_GetLastError
< 0x140001668  mov     edx, eax; a2
< 0x14000166a  mov     rcx, rbx; a1
< 0x14000166d  call    _ZNSolsEm; std::ostream::operator<<(ulong)
< 0x140001672  mov     rcx, rax; a1
< 0x140001675  mov     rax, cs:_refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_
< 0x14000167c  mov     rdx, rax; a2
< 0x14000167f  call    _ZNSolsEPFRSoS_E; std::ostream::operator<<(std::ostream & (*)(std::ostream &))
< 0x140001684  mov     eax, 1
< 0x140001689  jmp     loc_14000177D
---
> 0x14000168e  lea     rax, aFileCreatedOpe; "File created/opened successfully."
> 0x140001695  mov     rdx, rax; a2
> 0x140001698  mov     rax, cs:_refptr__ZSt4cout
> 0x14000169f  mov     rcx, rax; a1
> 0x1400016a2  call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc; std::operator<<<std::char_traits<char>>(std::ostream &,char const*)
> 0x1400016a7  mov     rcx, rax; a1
> 0x1400016aa  mov     rax, cs:_refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_
> 0x1400016b1  mov     rdx, rax; a2
> 0x1400016b4  call    _ZNSolsEPFRSoS_E; std::ostream::operator<<(std::ostream & (*)(std::ostream &))
> 0x1400016b9  mov     rax, [rbp+10h+data]
> 0x1400016bd  mov     rcx, rax; Str
> 0x1400016c0  call    strlen
> 0x1400016c5  mov     r8d, eax; nNumberOfBytesToWrite
> 0x1400016c8  lea     rcx, [rbp+10h+bytesWritten]
> 0x1400016cc  mov     rdx, [rbp+10h+data]; lpBuffer
> 0x1400016d0  mov     rax, [rbp+10h+hFile]
> 0x1400016d4  mov     qword ptr [rsp+70h+dwCreationDisposition], 0; lpOverlapped
> 0x1400016dd  mov     r9, rcx; lpNumberOfBytesWritten
> 0x1400016e0  mov     rcx, rax; hFile
> 0x1400016e3  mov     rax, cs:__imp_WriteFile
> 0x1400016ea  call    rax ; __imp_WriteFile
> 0x1400016ec  test    eax, eax
> 0x1400016ee  setz    al
> 0x1400016f1  test    al, al
> 0x1400016f3  jz      short loc_14000173D
> 0x14000173d  lea     rax, aFileWroteSucce; "File wrote successfully."
> 0x140001744  mov     rdx, rax; a2
> 0x140001747  mov     rax, cs:_refptr__ZSt4cout
> 0x14000174e  mov     rcx, rax; a1
> 0x140001751  call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc; std::operator<<<std::char_traits<char>>(std::ostream &,char const*)
> 0x140001756  mov     rcx, rax; a1
> 0x140001759  mov     rax, cs:_refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_
> 0x140001760  mov     rdx, rax; a2
> 0x140001763  call    _ZNSolsEPFRSoS_E; std::ostream::operator<<(std::ostream & (*)(std::ostream &))
> 0x140001768  mov     rax, [rbp+10h+hFile]
> 0x14000176c  mov     rcx, rax; _QWORD
> 0x14000176f  mov     rax, cs:__IAT_start__
> 0x140001776  call    rax ; __IAT_start__
> 0x140001778  mov     eax, 0
(0x140001783)> 
```

*Aliases: `alt`*

### `reset` command

Resets emulator, clearing all emulation history and restoring program counter back to entry point.

---
**WARNING**

This also clears undo history.

---

### `undo` command

Undo the last executed emulation command.

```console
(0x004014e0)> goto main
(0x00401150)> continue
(0x0040129f)> undo
(0x00401150)> undo
(0x004014e0)> 
```

## Emulation Artifacts

The following commands are used to display artifacts within the current emulation context.

### `actions` command

Lists the interesting actions (API calls) that have taken place with the current context.

```console
(0x140001783) > actions
address      action       handle    attributes
-----------  -----------  --------  ------------------------------------------------------
0x140001636  FileCreated  0x80      path='example.txt', mode='rw'
0x1400016ea  FileWritten  0x80      data=b'This is some sample data to write to the file.'
0x140001776  FileClosed   0x80
```

### `arguments` command

Lists the current function arguments based on the current call instruction.

- `-n`/`--num-args` directly sets the number of arguments to pull. (Useful for functions with variadic arguments)

```console
(0x1400016ea)> instruction
call    rax ; __imp_WriteFile
(0x1400016ea)> arguments
0x140009220: BOOL __stdcall __imp_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
  ordinal  location     type            width  name                    address     value        referenced data
---------  -----------  ------------  -------  ----------------------  ----------  -----------  ----------------------------------------------------
        0  rcx          handle              8  hFile                               0x80
        1  rdx          lpcvoid             8  lpBuffer                            0x140005000  b'This is some sample data to write to the file.\x..
        2  r8d          dword               4  nNumberOfBytesToWrite               0x2e
        3  r9           lpdword             8  lpNumberOfBytesWritten              0x117f7d4    b'\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00..
        4  stack[0x20]  lpoverlapped        8  lpOverlapped            0x0117f7a8  0x0
```

An address or [target variable](#target-variables) can be provided to list what the arguments *would be*
if the given function was called at the current context.

```console
(0x140001756)> instruction
mov     rcx, rax; a1
(0x140001756)> arguments WriteFile
0x140001798: BOOL __stdcall WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
  ordinal  location     type            width  name                    address     value        referenced data
---------  -----------  ------------  -------  ----------------------  ----------  -----------  ----------------------------------------------------
        0  rcx          handle              8  hFile                               0x140009310  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00..
        1  rdx          lpcvoid             8  lpBuffer                            0x140005092  b'File wrote successfully.\x00\x01\x01\x01\x00\x00..
        2  r8d          dword               4  nNumberOfBytesToWrite               0x2e
        3  r9           lpdword             8  lpNumberOfBytesWritten              0x117f7d4    b'.\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x0..
        4  stack[0x20]  lpoverlapped        8  lpOverlapped            0x0117f7a8  0x0
```

*Aliases: `arg`, `args`*

### `files` command

Lists the observed files that were created during emulation.

```console
(0x140001783) > files
handle    path         mode      size  closed    deleted    data
--------  -----------  ------  ------  --------  ---------  -------------------------------------------------
0x80      example.txt  rw          46  True      False      b'This is some sample data to write to the file.'
```

The contents of a file can be extracted by providing the handle as an argument.
This data will be provided in raw bytes, so it is best to redirect the output to a file.

```console
(0x140001783) > files 0x80 > example.txt
(0x140001783) > !cat example.txt
This is some sample data to write to the file.
```

### `memory` command

Lists the currently allocated blocks of memory.

```console
(0x140001756)> memory
start        end            size
-----------  -----------  ------
0x0117f000   0x01180000     4096
0x140001000  0x140008000   28672
0x140009000  0x14000c000   12288
```

An address or [target variable](#target-variables) can be provided to read the memory at the given address.

**Args:**
- `-n`/`--num` sets the number of bytes to read.
- `--raw` writes out raw bytes instead of a hex dump.

```console
(0x140001756)> memory 0x140005092 -n 30
140005092:  46 69 6C 65 20 77 72 6F  74 65 20 73 75 63 63 65  File wrote succe
1400050A2:  73 73 66 75 6C 6C 79 2E  00 01 01 01 00 00        ssfully.......
(0x140001756)> memory 0x140005092 -n 30 --raw > data.bin
```

*Aliases: `mem`*

### `objects` command

Lists the high-level objects created within the current emulation context.


### `parameters` command

Lists the function arguments passed in as parameters for the current function.

```console
(0x00401150)> parameters
0x00401150: int __cdecl _main(int argc, const char **argv, const char **envp);
  ordinal  location    type             width  name    address     value    referenced data
---------  ----------  -------------  -------  ------  ----------  -------  -----------------
        0  stack[0x0]  int                  4  argc    0x0117f804  0x0
        1  stack[0x4]  const char **        4  argv    0x0117f808  0x0
        2  stack[0x8]  const char **        4  envp    0x0117f80c  0x0
```

*Aliases: `param`, `params`*

### `registers` command

Lists the current values of the registers.

**Args:**
- `-a`/`--all` will also include registers with a zero value.

```console
(0x140001756)> registers
family    value
--------  -----------
rax       0x140009310
rcx       0x140009310
rdx       0x140005092
rbp       0x0117f7e8
rsp       0x0117f788
rip       0x140001756
r8        0x0000002e
r9        0x0117f7d4
eflags    0x00000044
```

The name of a register can be provided to display the value of that register.

```console
(0x140001756)> registers ah
0x00000093
```

*Aliases: `reg`, `regs`*

### `regkeys` command

Lists the registry key objects created within the current context.

### `services` command

Lists the service objects created within the current context.

### `stdout` command

Outputs emulated stdout results.

```console
(0x004011bc)> stdout
Hello World!
Test string with key 0x02
The quick brown fox jumps over the lazy dog.
Oak is strong and also gives shade.
Acid burns holes in wool cloth.
```

### `variables` command

Lists all the variables (named data) encountered during emulation.

```console
(0x00401174)> variables
address     stack_offset    name             type             size  value
----------  --------------  ---------------  -------------  ------  --------------------------------------------------
0x0040c000                  aIdmmnVnsme      char[13]           13  b'Hello World!\x00'
0x0040c010                  aVgqvQvpkleUkvj  char[26]           26  b'Test string with key 0x02\x00'
0x0040c02c                  aWkfRvjHAqltmEl  char[45]           45  b'The quick brown fox j... over the lazy dog.\x00'
0x0040c05c                  aKeoMwWpvkjcEjE  char[36]           36  b'Oak is strong and also gives shade.\x00'
0x0040c080                  aDflaGpwkvMjiVL  char[32]           32  b'Acid burns holes in wool cloth.\x00'
0x0040c0a0                  aEgruGhbBiauCge  char[35]           35  b'Cats and dogs each hate the other.\x00'
0x0040c0c4                  aCv3gV3pargv3qf  char[36]           36  b"Open the crate but don't break the g"
0x0040c0f0                  aC               char                1  84
0x0040c114                  asc_40C114       char[11]           11  b'1234567890\x00'
0x0040c120                  aQfbwfsqlFppb    char[15]           15  b'CreateProcessA\x00'
0x0040c130                  aTsudfs          char[7]             7  b'StrCat\x00'
0x0040c138                  byte_40C138      byte[8]             8  b'ASP.NET\x00'
0x0040c140                  a5VTr4vTrv4tV    char[21]           21  b'kdjsfjf0j24r0j240r2j0'
0x0040c15c                  aAkjdgbaKjgdbjk  char[21]           21  b'32897412389471982470\x00'
0x0040c174                  asc_40C174       char                1  84
0x0040c19c                  a4               char                1  67
0x0040c1c4                  asc_40C1C4       char                1  84
0x0040c1f8                  aLmfoghknlmgfoh  char[78]           78  b'329087413289074981347...6598123056231895712\x00'
0x0040c248                  Format           char[4]             4  b'%s\n\x00'
0x0040c24c                  aS_0             char[4]             4  b'%s\n\x00'
0x0117f7ec  -0x8            a1               byte *              4  4244037
0x0117f7f0  -0x4            a2               char                1  103
0x0117f804  0x10            argc             int                 4  0
0x0117f808  0x14            argv             const char **       4  0
0x0117f80c  0x18            envp             const char **       4  0
```

An address or variable name can be given to extract out data.

**Args:**
- `--raw` writes out raw bytes.

```console
(0x00401174)> variables aIdmmnVnsme 
b'Hello World!\x00'
(0x00401174)> variables aIdmmnVnsme --raw > data.bin
```

*Aliases: `var`, `vars`*

## Emulation Info

### `branch_history` command

Lists the starting addresses for each basic block within the branching path of the current execution context.

*"forced" means the branching from the previous block was forced even though the emulated opcodes would not have dictated 
that direction.*

**Args:**
- `-i`/`--include-instructions` includes the instruction text for the head of each block.

```console
(0x140001763)> branch_history -i
address      forced    instruction
-----------  --------  -----------------------------------------------------------------
0x1400015e0  False     push    rbp
0x14000168e  False     lea     rax, aFileCreatedOpe; "File created/opened successfully."
0x14000173d  False     lea     rax, aFileWroteSucce; "File wrote successfully."
```

*Aliases: `bhist`*

### `call_history` command

Lists the history of called functions.

```console
(0x140001783)> call_history
address      function     args
-----------  -----------  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------
0x1400015eb  _main
0x140001636  CreateFileA  lpFileName=0x14000502f, dwDesiredAccess=0xc0000000, dwShareMode=0x3, lpSecurityAttributes=0x0, dwCreationDisposition=0x2, dwFlagsAndAttributes=0x80, hTemplateFile=0x0
0x1400016a2  operator<<   param_1=0x10000000, param_2=0x140005058
0x1400016b4  operator<<   this=0x10000000, param_1=0x1400017d8
0x1400016c0  strlen       _Str=0x140005000
0x1400016ea  WriteFile    hFile=0x80, lpBuffer=0x140005000, nNumberOfBytesToWrite=0x2e, lpNumberOfBytesWritten=0x117f7d4, lpOverlapped=0x0
0x140001751  operator<<   param_1=0x10000000, param_2=0x140005092
0x140001763  operator<<   this=0x10000000, param_1=0x1400017d8
0x140001776  CloseHandle  hObject=0x80
```

*Aliases: `chist`*

### `disassembly` command

Prints a few lines of disassembly in both directions from the current instruction or given address/[target variable](#target-variables).

```console
(0x00401186)> disassembly
0x00401150: int __cdecl _main(int argc, const char **argv, const char **envp);
    ...
    0x0040115d: push    offset Format; "%s\n"
    0x00401162: call    _printf
    0x00401167: add     esp, 8
    0x0040116a: push    offset aVgqvQvpkleUkvj; "Vgqv\"qvpkle\"ukvj\"ig{\"2z20"
    0x0040116f: push    offset aS_0; "%s\n"
    0x00401174: call    _printf
    0x00401179: add     esp, 8
    0x0040117c: push    offset aWkfRvjHAqltmEl; "Wkf#rvj`h#aqltm#el{#ivnsp#lufq#wkf#obyz"...
    0x00401181: push    offset aS_1; "%s\n"
 -> 0x00401186: call    _printf
    0x0040118b: add     esp, 8
    0x0040118e: push    offset aKeoMwWpvkjcEjE; "Keo$mw$wpvkjc$ej`$ehwk$cmraw$wle`a*"
    0x00401193: push    offset aS_2; "%s\n"
    0x00401198: call    _printf
    0x0040119d: add     esp, 8
    0x004011a0: push    offset aDflaGpwkvMjiVL; "Dfla%gpwkv%mji`v%lk%rjji%fijqm+"
    0x004011a5: push    offset aS_3; "%s\n"
    0x004011aa: call    _printf
    0x004011af: add     esp, 8
    ...
(0x00401186)> disassembly op0
0x004012a0: int _printf(const char *const Format, DWORD a2, ...);
 -> 0x004012a0: push    0Ch; a2
    0x004012a2: push    offset stru_40B3D0; a1
    0x004012a7: call    __SEH_prolog4
    0x004012ac: xor     eax, eax
    0x004012ae: xor     esi, esi
    0x004012b0: cmp     [ebp+Format], esi
    0x004012b3: setnz   al
    0x004012b6: cmp     eax, esi
    0x004012b8: jnz     short loc_4012D7
    0x004012ba: call    __errno
    ...
```

*Aliases: `dis`*

### `dump` command

Generates a report containing the results of a number of different commands.

```console
(0x140001763)> dump | head -n 20
# Rugosa Emulation Report
------------  ---------------------------------
File          /home/ubuntu/dev/data/binary.exe
Disassembler  IDA
Processor     x86
Compiler      Visual C++
Bit size      32
Endianness    LE
Entry Point   0x004014e0
------------  ---------------------------------


se
## Disassembly
0x1400015e0: __int64 __fastcall main();
    ...
    0x1400016f3: jz      short loc_14000173D
    0x14000173d: lea     rax, aFileWroteSucce; "File wrote successfully."
    0x140001744: mov     rdx, rax; a2
    0x140001747: mov     rax, cs:_refptr__ZSt4cout
(0x140001763)> dump > report.txt
```

### `exec_history` command

Lists the addresses of the instructions that have been emulated.

**Args:**
- `-i`/`--include-instructions` includes instruction text for each address.

```console
(0x140001763)> exec_history -i | head
address      instruction
-----------  ------------------------------------------------------------------------------------------------------------------------------------
0x1400015e0  push    rbp
0x1400015e1  push    rbx
0x1400015e2  sub     rsp, 68h
0x1400015e6  lea     rbp, [rsp+60h]
0x1400015eb  call    __main
0x1400015f0  lea     rax, aThisIsSomeSamp; "This is some sample data to write to th"...
0x1400015f7  mov     [rbp+10h+data], rax
0x1400015fb  mov     [rsp+70h+hTemplateFile], 0; hTemplateFile
```

*Aliases: `ehist`*

### `spdiff` command

Prints the difference between the current stack pointer and the stack pointer at the beginning of the function.

```console
(0x1400015e2)> spdiff
0x10
```

---
**TIP**

To have the current spdiff always displayed in the prompt, set the `display_spdiff` setting.

```console
(0x1400015e2)> set display_spdiff True
display_spdiff - was: False
now: True
(0x1400015e2 0x10)> 
```

---


## Extras

Since the shell tool is written using [cmd2](https://cmd2.readthedocs.io) we automatically benefit from some
of the features provided by that library.


### Startup Commands

The shell can be provided some initial commands upon startup using a number of different methods.

- Provided at the end of the `rugosa` command.

```console
rugosa binary.exe "set prompt_color red" "goto 0x1234" "dis"
```

- Provided as a file of newline delimited commands using `@` or `-s`/`--startup-script`

```console
rugosa binary.exe @mycommands.txt
```

- Set the `RUGOSA_STARTUP_SCRIPT` environment variable to a file path containing commands.

```console
export RUGOSA_STARTUP_SCRIPT="~/mycommands.txt"
rugosa binary.exe
```


Setting up some startup commands can be helpful for things such as providing your own
[aliases](https://cmd2.readthedocs.io/en/stable/features/shortcuts_aliases_macros.html#aliases), 
[macros](https://cmd2.readthedocs.io/en/stable/features/shortcuts_aliases_macros.html#macros), 
or [settings](#settings).


#### Automation

Adding `quit` to the end of the commands will cause the shell not to spawn and return you back to the terminal. 
Useful for repeatable or common one-off tasks.

```console
$ echo "
  # Emulates function at 0x401150 and returns emulated variables.
  goto 0x401150
  continue --call-depth 2
  vars
  quit
  " > script.txt
$ rugosa binary.exe --nologo -s script.txt | head
address     stack_offset    name                                         type         size  value
----------  --------------  -------------------------------------------  ---------  ------  --------------------------------------------------
0x0040c000                  s_Idmmn!Vnsme_0040c000                       string         13  b'Hello World!\x00'
0x0040c010                  s_Vgqv"qvpkle"ukvj"ig{"2z20_0040c010         string         26  b'Test string with key 0x02\x00'
0x0040c02c                  s_Wkf#rvj`h#aqltm#el{#ivnsp#lufq#w_0040c02c  string         45  b'The quick brown fox j... over the lazy dog.\x00'
0x0040c05c                  s_Keo$mw$wpvkjc$ej`$ehwk$cmraw$wle_0040c05c  string         36  b'Oak is strong and also gives shade.\x00'
0x0040c080                  s_Dfla%gpwkv%mji`v%lk%rjji%fijqm+_0040c080   string         32  b'Acid burns holes in wool cloth.\x00'
0x0040c0a0                  s_Egru&ghb&biau&cgen&ngrc&rnc&irnc_0040c0a0  string         35  b'Cats and dogs each hate the other.\x00'
0x0040c0c4                  DAT_0040c0c4                                 undefined       1  79
0x0040c0f0                  DAT_0040c0f0                                 undefined       1  84
```


```console
$ rugosa binary.exe --nologo funcs quit | head
start       end         name
----------  ----------  ------------------------------
0x00401000  0x0040102b  FUN_00401000
0x00401030  0x00401143  FUN_00401030
0x00401150  0x004012a0  FUN_00401150
0x004012a0  0x0040133c  _printf
0x0040133c  0x0040134f  FUN_0040133c
0x0040134f  0x00401365  __get_printf_count_output
0x00401365  0x0040138e  _fast_error_exit
0x0040138e  0x004014e0  ___tmainCRTStartup
```

### Settings

Along with the [settings](https://cmd2.readthedocs.io/en/stable/features/settings.html) provided by cmd2,
rugosa includes a few custom settings to control emulation and display settings.

These can be viewed and updated using the `set` command.

```console
(0x004014e0)> set
Name                  Value                           Description                                                 
==================================================================================================================
allow_style           Terminal                        Allow ANSI text style sequences in output (valid values:    
                                                      Always, Never, Terminal)                                    
always_show_hint      False                           Display tab completion hint even when completion suggestions
                                                      print                                                       
branch_tracking       True                            When forcing emulation to go down the incorrect branch in   
                                                      order to reach the desired end address, branch_tracking is  
                                                      used to try to tweak the registers to make the branching    
                                                      condition true. This can be helpful to ensure the rest of   
                                                      the emulation is done correctly, however this will cause    
                                                      emulation to run slower. So this option allows you to turn  
                                                      it off when the feature is not necessary.                   
debug                 True                            Show full traceback on exception                            
display_instruction   False                           Display current instruction in prompt                       
display_spdiff        False                           Display the stack pointer diff in prompt                    
echo                  False                           Echo command issued into output                             
editor                vim                             Program used by 'edit'                                      
feedback_to_output    False                           Include nonessentials in '|', '>' results                   
max_completion_items  50                              Maximum number of CompletionItems to display during tab     
                                                      completion                                                  
max_instructions      10000                           Maximum number of instructions to allow when emulating loop 
                                                      following code. This is used since it is possible that the  
                                                      end instruction would never get reached.                    
max_undo_items        20                              Maximum number of undo items to keep. Set to 0 to turn off  
                                                      undo.                                                       
prompt_color          green                           Color of prompt. 'reset' disables color                     
quiet                 False                           Don't print nonessential feedback                           
tablefmt              simple                          Format for tables                                           
timing                False                           Report execution times
```

```console
(0x004014e0)> set display_instruction True
display_instruction - was: False
now: True
(0x004014e0: call    ___security_init_cookie)> 
```


### Shelling into a Python Interpreter

At any point, a python interpreter can be opened using the `py` or `ipy` command. 
This allows for more advanced techniques that may not be possible with the exposed shell commands.

Upon opening up the interpreter, the following variables will be available in the namespace:

- `ctx` - The current ProcessorContext instance which holds all the emulation artifacts.
- `emu` - The current Emulator instance which provides emulation control for creating new contexts.
- `dis` - The dragodis Disassembler instance for accessing disassembly information.

```console
(0x140001125)> py
Python 3.11.6 (main, Jan 16 2024, 16:42:17) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.

Use `Ctrl-D` (Unix) / `Ctrl-Z` (Windows), `quit()`, `exit()` to exit.
Run CLI commands with: app("command ...")

>>> ctx.instruction
<rugosa.emulation.x86_64.instruction.x86_64Instruction object at 0x7f9ebca8ac90>
>>> ctx.operands
[<x86_64Operand 0x140001125:0 : rbp = 18349056 : width = 8>]
>>> ctx.execute(end=0x14000112D)
>>> exit()
Now exiting Python shell...
(0x14000112d)> 
```

If you need to update the context instance, set the `self.ctx` field for your new context to be applied after
exiting the interpreter.

```console
>>> ctx, args = emu.get_function_arg_values(0x40103a)
>>> args
[4243456, 1]
>>> self.ctx = ctx
```


### Target Variables

Most of the rugosa commands that accept an address as an argument can also accept an identifier instead.

The following are valid identifiers:

- integer or `0x` prefixed hex number - converts directly to an address.
- `.` - The address of the current instruction.
- `sp` - The current stack pointer. (alias to `rsp`)
- `opX` - The referenced address or value within the `X` position. (e.g. `op0` for the first operand)
- `argX` - The argument value within the `X` position if currently on a call instruction. (e.g. `arg0` for the first argument)
- *register name* - The value within a register. (e.g. `edi`)
- *variable name* - The address of a given variable seen in the [variables](#variables-command) command. (e.g. `s_Data` or `aData`)
- *function name* - The starting address of a given function name seen in the [functions](#functions-command) command. Extraneous underscores will be stripped. (e.g. `sub_401030`)
- *import name* - The address of an import symbol. (e.g. `WriteFile`)

