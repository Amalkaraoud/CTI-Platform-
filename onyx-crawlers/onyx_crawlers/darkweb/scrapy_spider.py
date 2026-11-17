"""
ONYX CTI - Scrapy collection layer for the dark web (report section 4.1: Scrapy + Playwright + BS4).

Requests leave through the Privoxy HTTP bridge of the `tor-proxy` container (Tor SOCKS behind it),
with a rotating Tor-Browser User-Agent, one request at a time per domain, a polite delay and a
bounded crawl depth. Circuit rotation (NEWNYM) is handled by the `tor-proxy` rotator, and a
kill switch (TOR_KILL_SWITCH=true) stops the crawl instead of ever falling back to a direct connection.

Scrapy is imported lazily by `build_spider`, so importing this module (and testing `page_extract`)
does not require it. Run a crawl:

    python -m onyx_crawlers.darkweb.scrapy_spider http://exampleonionaddress.onion/ --depth 1
"""
from __future__ import annotations

import os
import random
from typing import Any

from onyx_crawlers.darkweb.page_extract import extract_page

TOR_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:115.0) Gecko/20100101 Firefox/115.0",
]


def scrapy_settings(env: dict[str, str] | None = None) -> dict[str, Any]:
    env = env if env is not None else dict(os.environ)
    return {
        "BOT_NAME": "onyx-crawler",
        "ROBOTSTXT_OBEY": False,                       # hidden services rarely publish one; scope is the seed list
        "CONCURRENT_REQUESTS": int(env.get("CRAWLER_MAX_CONCURRENT", "3")),
        "CONCURRENT_REQUESTS_PER_DOMAIN": 1,           # one in-flight request per domain (per-domain circuit)
        "DOWNLOAD_DELAY": float(env.get("CRAWLER_REQUEST_DELAY", "5.0")),
        "RANDOMIZE_DOWNLOAD_DELAY": True,
        "DOWNLOAD_TIMEOUT": int(env.get("CRAWLER_REQUEST_TIMEOUT", "60")),
        "RETRY_TIMES": 2,
        "COOKIES_ENABLED": False,
        "TELNETCONSOLE_ENABLED": False,
        "DEPTH_LIMIT": 1,
        "LOG_LEVEL": env.get("ONYX_LOG_LEVEL", "INFO"),
        "ONYX_PROXY": f"http://{env.get('TOR_HOST', 'tor-proxy')}:{env.get('TOR_PRIVOXY_PORT', '8118')}",
        "ONYX_KILL_SWITCH": env.get("TOR_KILL_SWITCH", "false").lower() == "true",
    }


def build_spider():
    """Create the spider class (imports Scrapy). Raises ImportError with guidance if it is missing."""
    try:
        import scrapy
        from scrapy.exceptions import CloseSpider
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError("Scrapy is required for the dark-web crawler: pip install scrapy") from exc

    class OnyxOnionSpider(scrapy.Spider):
        name = "onyx_onion"

        def __init__(self, seeds: list[str] | None = None, *a, **kw):
            super().__init__(*a, **kw)
            self.seeds = [s for s in (seeds or []) if s.startswith(("http://", "https://"))]
            self.results: list[dict[str, Any]] = []

        def _request(self, url: str, **kw):
            proxy = self.settings.get("ONYX_PROXY")
            return scrapy.Request(url, headers={"User-Agent": random.choice(TOR_USER_AGENTS)},
                                  meta={"proxy": proxy}, callback=self.parse, errback=self.on_error, **kw)

        def start_requests(self):
            if self.settings.getbool("ONYX_KILL_SWITCH"):
                raise CloseSpider("kill switch active: refusing to crawl")
            for url in self.seeds:
                yield self._request(url)

        def parse(self, response):
            page = extract_page(response.text, response.url)
            page["status"] = response.status
            self.results.append(page)
            yield page
            depth = response.meta.get("depth", 0)
            if depth < self.settings.getint("DEPTH_LIMIT"):
                host = page["domain"]
                for link in page["links"]:
                    if (link.split("/")[2] if "//" in link else "") == host:    # stay on the same hidden service
                        yield self._request(link)

        def on_error(self, failure):
            self.logger.warning("fetch failed: %s", failure.getErrorMessage())

    return OnyxOnionSpider


def run(seeds: list[str], depth: int = 1) -> list[dict[str, Any]]:  # pragma: no cover - needs Scrapy and Tor
    from scrapy.crawler import CrawlerProcess

    settings = scrapy_settings()
    settings["DEPTH_LIMIT"] = max(0, min(depth, 3))
    process = CrawlerProcess(settings)
    crawler = process.create_crawler(build_spider())
    process.crawl(crawler, seeds=seeds)
    process.start()
    return list(crawler.spider.results)


if __name__ == "__main__":  # pragma: no cover
    import argparse
    import json

    ap = argparse.ArgumentParser(description="ONYX dark-web Scrapy crawler")
    ap.add_argument("seeds", nargs="+")
    ap.add_argument("--depth", type=int, default=1)
    args = ap.parse_args()
    print(json.dumps(run(args.seeds, args.depth), ensure_ascii=False, indent=2))
