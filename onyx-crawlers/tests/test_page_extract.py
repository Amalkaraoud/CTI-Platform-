"""Page extraction used by the Scrapy spider (bs4 only) and the spider's settings (no Scrapy needed)."""
import importlib.util
import sys
from pathlib import Path

base = Path(__file__).resolve().parents[1] / "onyx_crawlers" / "darkweb"
def load(name, modname):
    sp = importlib.util.spec_from_file_location(modname, base / f"{name}.py")
    m = importlib.util.module_from_spec(sp); sys.modules[modname] = m; sp.loader.exec_module(m); return m

for pkg in ("onyx_crawlers", "onyx_crawlers.darkweb"):
    sys.modules.setdefault(pkg, importlib.util.module_from_spec(importlib.util.spec_from_loader(pkg, loader=None)))
    sys.modules[pkg].__path__ = []
pe = load("page_extract", "onyx_crawlers.darkweb.page_extract")
ss = load("scrapy_spider", "onyx_crawlers.darkweb.scrapy_spider")

HTML = """<html><head><title> Leak </title><script>evil()</script></head><body>
<p>dump   of data</p><a href="/a">a</a><a href="http://x.onion/b">b</a><a href="javascript:alert(1)">j</a>
<a href="/a">dup</a></body></html>"""


def test_extract_strips_scripts_and_resolves_safe_links():
    p = pe.extract_page(HTML, "http://site.onion/index")
    assert p["title"] == "Leak" and "evil" not in p["text"] and "dump of data" in p["text"]
    assert p["links"] == ["http://site.onion/a", "http://x.onion/b"]
    assert p["domain"] == "site.onion" and len(p["content_hash"]) == 64


def test_same_text_same_hash():
    assert pe.extract_page(HTML, "http://a.onion/")["content_hash"] == pe.extract_page(HTML, "http://b.onion/")["content_hash"]


def test_settings_enforce_politeness_and_proxy():
    s = ss.scrapy_settings({"TOR_KILL_SWITCH": "true", "CRAWLER_REQUEST_DELAY": "7"})
    assert s["CONCURRENT_REQUESTS_PER_DOMAIN"] == 1 and s["DOWNLOAD_DELAY"] == 7.0
    assert s["ONYX_PROXY"] == "http://tor-proxy:8118" and s["ONYX_KILL_SWITCH"] is True
