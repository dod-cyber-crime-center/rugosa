import pytest

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


@pytest.mark.skipif(yara.YARA_VERSION < "4.3.0", reason="YARA < 4.3.0")
def test_string_match(disassembler):
    """
    Tests the newer string match object introduced in YARA 4.3.0
    """
    rule = yara.compile(source=rule_text)
    matches = rule.match(disassembler, legacy_strings=False)
    assert matches
    assert len(matches) == 1
    match = matches[0]
    strings = match.strings
    assert strings
    assert len(strings) == 2
    string = strings[0]
    assert string.identifier == "$string_1"
    assert string.is_xor() is False
    assert len(string.instances) == 1
    instance = string.instances[0]
    assert instance.matched_data == b'Idmmn!Vnsme'
    assert instance.offset == 0x40C000
    assert instance.xor_key == 0
