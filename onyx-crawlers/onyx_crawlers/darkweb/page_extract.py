"""Framework-neutral page extraction shared by the Scrapy spider and the httpx spiders. Needs only bs4."""
from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

MAX_TEXT = 200_000
MAX_LINKS = 500


def extract_page(html: str, url: str) -> dict[str, Any]:
    """Title, visible text, absolute http(s) links and a SHA-256 of the text (content-level dedup)."""
    soup = BeautifulSoup(html or "", "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = " ".join(soup.get_text(" ").split())[:MAX_TEXT]
    links: list[str] = []
    for a in soup.find_all("a", href=True):
        absolute = urljoin(url, a["href"])
        if urlparse(absolute).scheme in ("http", "https") and absolute not in links:
            links.append(absolute)
        if len(links) >= MAX_LINKS:
            break
    return {
        "url": url,
        "domain": urlparse(url).hostname or "",
        "title": (soup.title.string or "").strip() if soup.title and soup.title.string else "",
        "text": text,
        "links": links,
        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }
