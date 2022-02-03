# Regex Utility

Rugosa includes a regex utility for performing searches within the context
of a Dragodis disassembler.

To use, simply import `rugosa.re` instead of `re`.
The interface more or less matches Python's builtin [re](https://docs.python.org/3/library/re.html) module.
The only difference is that you get virtual addresses
for offsets instead of direct offsets.

When performing matches or searches, simply provide the disassembler object instead of raw data.

```python
import dragodis
from rugosa import re


ptn = re.compile(b"\x56\x56\x56\x56\x56\xe8\x9c\x12\x00\x00")

with dragodis.open_program(r"C:\input.exe") as dis:
    match = ptn.search(dis)
    assert match
    assert match.start() == 0x4012c5
    
    # Iterate all the functions that have the pattern.
    for func in ptn.find_functions(dis):
        print(func.name)
        print(func.start)
```