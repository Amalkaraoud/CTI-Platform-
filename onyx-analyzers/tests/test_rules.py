"""YARA / Sigma generation. Sigma output is parsed with PyYAML; YARA is checked structurally
(no YARA engine is available in the test environment, so compilation is NOT verified here)."""
import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

spec = importlib.util.spec_from_file_location("rules", Path(__file__).resolve().parents[1] / "onyx_analyzers/rules.py")
rules = importlib.util.module_from_spec(spec)
sys.modules["rules"] = rules
spec.loader.exec_module(rules)

IOCS = [
    {"type": "domain", "value": "Evil-C2.example.com"},
    {"type": "ipv4", "value": "8.8.4.4"},
    {"type": "ipv4", "value": "10.0.0.5"},                       # private: dropped
    {"type": "url", "value": "http://evil-c2.example.com/gate.php?id=1"},
    {"type": "sha256", "value": "A" * 64},
    {"type": "md5", "value": "b" * 32},
    {"type": "sha256", "value": "short"},                         # malformed: dropped
]


def test_sanitize_filters_and_normalises():
    s = rules.sanitize_indicators(IOCS)
    assert s["domain"] == ["evil-c2.example.com"] and s["ipv4"] == ["8.8.4.4"]
    assert s["sha256"] == ["a" * 64] and s["md5"] == ["b" * 32] and "sha1" not in s


def test_sigma_rules_are_valid_yaml_with_required_fields():
    out = rules.generate_rules("APT Test", IOCS, ["T1059.001", "bogus"], level="high", today="2026/11/17")
    assert len(out["sigma"]) == 4
    for r in out["sigma"]:
        doc = yaml.safe_load(r["text"])
        for k in ("title", "id", "status", "description", "logsource", "detection", "level", "tags", "date"):
            assert k in doc, k
        assert doc["detection"]["condition"] == "selection" and doc["tags"] == ["attack.t1059.001"]
        assert doc["id"] == r["rule_id"] and doc["level"] == "high"


def test_rule_ids_are_deterministic_and_distinct():
    a = rules.generate_rules("X", IOCS, today="2026/01/01")
    b = rules.generate_rules("X", IOCS, today="2026/02/02")
    assert [r["rule_id"] for r in a["sigma"]] == [r["rule_id"] for r in b["sigma"]]
    assert len({r["rule_id"] for r in a["sigma"]}) == 4


def test_hostile_values_cannot_inject_syntax():
    hostile = [{"type": "domain", "value": "a.com'\n    condition: all of them"},
               {"type": "url", "value": "http://x.com/\"; } rule pwn { condition: true"},
               {"type": "sha256", "value": "0" * 63 + "'"}]
    out = rules.generate_rules("evil'name\"\nrule x {", hostile, [])
    assert out["sigma"] == [] and out["yara"] is None            # nothing valid survives
    name_only = rules.generate_rules("evil'name\"\nrule x {", [{"type": "domain", "value": "ok.example.com"}])
    doc = yaml.safe_load(name_only["sigma"][0]["text"])           # name with quotes/newline stays one scalar
    assert "evil'name" in doc["title"] and "\n" not in doc["title"]
    y = name_only["yara"]
    assert len(re.findall(r"^rule ", y, re.M)) == 1 and "\n" not in y.split("threat = ")[1].split("\n")[0][:-1] and re.search(r"^rule ONYX_[A-Za-z0-9_]+_[0-9a-f]{8}$", y, re.M)
    assert 'threat = "evil\'name\\"' in y


def test_yara_structure_and_hash_conditions():
    y = rules.generate_yara("APT Test", rules.sanitize_indicators(IOCS), ["T1566"], today="2026-11-17")
    assert y.startswith('import "hash"') and "strings:" in y and "condition:" in y
    assert y.count("{") == y.count("}") == 1
    assert '$s0 = "evil-c2.example.com" ascii wide nocase' in y
    assert 'hash.sha256(0, filesize) == "' + "a" * 64 + '"' in y and "any of ($s*)" in y
    assert 'attack = "T1566"' in y


def test_yara_without_strings_or_hashes_is_none():
    assert rules.generate_yara("n", {}) is None


@pytest.mark.parametrize("bad", ["", None, "x"])
def test_unknown_level_falls_back(bad):
    out = rules.generate_sigma("n", {"domain": ["a.example.com"]}, level=bad)
    assert yaml.safe_load(out[0]["text"])["level"] == "medium"
