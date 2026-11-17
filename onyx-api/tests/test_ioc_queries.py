import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("ioc_queries", Path(__file__).resolve().parents[1] / "onyx_api/services/ioc_queries.py")
q = importlib.util.module_from_spec(spec); sys.modules["ioc_queries"] = q; spec.loader.exec_module(q)

DATA = [{"value": "1.1.1.1", "type": "ipv4", "severity": "high", "source": "feodo"},
        {"value": "evil.com", "type": "domain", "severity": "medium", "source": "urlhaus"},
        {"value": "EVIL.org", "type": "domain", "source": "misp"}]


def test_filters_combine():
    assert [i["value"] for i in q.filter_iocs(DATA, ioc_type="domain")] == ["evil.com", "EVIL.org"]
    assert [i["value"] for i in q.filter_iocs(DATA, ioc_type="domain", text="evil.o")] == ["EVIL.org"]
    assert q.filter_iocs(DATA, severity="high", source="urlhaus") == []


def test_pagination_and_limit_caps():
    assert [i["value"] for i in q.filter_iocs(DATA, limit=1, offset=1)] == ["evil.com"]
    big = [{"value": str(n)} for n in range(5000)]
    assert len(q.filter_iocs(big, limit=10**9)) == q.MAX_LIMIT
    assert len(q.filter_iocs(big, limit=-5)) == 1 and q.filter_iocs(big, offset=-3)[0]["value"] == "0"


def test_stats_defaults_missing_fields():
    s = q.stats(DATA)
    assert s["total"] == 3 and s["by_type"] == {"ipv4": 1, "domain": 2}
    assert s["by_severity"] == {"high": 1, "medium": 2}      # missing severity counts as medium
