"""STIX custom properties: x_onyx_* on the wire, legacy onyx_* still accepted on input."""
import importlib.util
import sys
from pathlib import Path

import pytest

try:
    import orjson  # noqa: F401
except ImportError:                                   # only used for serialisation helpers, not by these tests
    import json, types
    sys.modules["orjson"] = types.SimpleNamespace(dumps=lambda o, **k: json.dumps(o).encode(), loads=json.loads)
spec = importlib.util.spec_from_file_location("stix_mod", Path(__file__).resolve().parents[2] / "onyx_core/models/stix.py")
stix = importlib.util.module_from_spec(spec); sys.modules["stix_mod"] = stix; spec.loader.exec_module(stix)

ID = "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"


def test_dump_by_alias_uses_x_onyx_names():
    o = stix.STIXBase(id=ID, type="indicator", onyx_source="feodo", onyx_tags=["c2"])
    d = o.model_dump(mode="json", by_alias=True)
    assert d["x_onyx_source"] == "feodo" and d["x_onyx_tags"] == ["c2"] and "onyx_source" not in d


def test_legacy_documents_still_load():
    old = {"id": ID, "type": "indicator", "onyx_source": "legacy", "onyx_tags": ["a"]}
    assert stix.STIXBase(**old).onyx_source == "legacy"
    new = {"id": ID, "type": "indicator", "x_onyx_source": "new"}
    assert stix.STIXBase(**new).onyx_source == "new"
