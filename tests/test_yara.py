
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


def test_match(disassembler):
    rule = yara.compile(source=rule_text)
    matches = rule.match(disassembler)
    assert matches
    assert [match.strings for match in matches] == [
        [(0x40C000, '$string_1', b'Idmmn!Vnsme'),
         (0x40C080, '$string_2', b'Dfla%gpwkv%mji`v%lk%rjji%fijqm+')]
    ]
    matches = rule.match(disassembler, segment=".text")
    assert not matches
    matches = rule.match(disassembler, segment=".data")
    assert matches
    assert [match.strings for match in matches] == [
        [(0x40C000, '$string_1', b'Idmmn!Vnsme'),
         (0x40C080, '$string_2', b'Dfla%gpwkv%mji`v%lk%rjji%fijqm+')]
    ]
