# YARA Utility

Rugosa includes a utility for running YARA within the context of a disassembly.

This utility extends and overwrites the existing YARA API to work correctly within a Dragodis context.
This will make all offsets return virtual addresses instead of direct file offsets.


```python
import dragodis
from rugosa import yara

rule_text = """
rule MyStrings 
{
    strings:
        $string_1 = "Idmmn!Vnsme"
        $string_2 = "Dfla%gpwkv%mji`v%lk%rjji%fijqm+"
    condition:
        any of them
}
"""

# Compile a yara rule in the same way as the original yara library.
rule = yara.compile(source=rule_text)

with dragodis.open_program(r"C:\input.exe") as dis:
    matches = rule.match(dis)  # Run rule on entire disassembled code.

    # Can also be used to run on segments.
    matches = rule.match(dis, segment=".text")

    # We can also just look for matching strings.
    for offset, identifier in rule.match_strings(dis):
        ...
    for offset, identifier in rule.match_strings(dis, segment=".text"):
        ...

    # We can also get the Function objects containing matches.
    for func in rule.find_functions(dis):
        print(func.name)
        print(func.start)
```