from __future__ import annotations

import re
from functools import lru_cache
from urllib.parse import quote_plus, urlsplit

import requests

from .config import PHISH_FEED_URLS, REQUEST_TIMEOUT, USER_AGENT
from .scan_context import ScanContext
from .url_features import _is_ip_like, _same_registered_domain

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None


def _feature_web_traffic(context: ScanContext) -> int | None:
    if not context.registered_domain:
        return None
    rank = _fetch_tranco_rank(context.registered_domain)
    if rank is None:
        return None
    context.evidence["web_traffic"] = f"Tranco rank = {rank}"
    if rank < 100_000:
        return 1
    return 0


def _feature_page_rank(context: ScanContext) -> int | None:
    if not context.registered_domain:
        return None
    rank = _fetch_tranco_rank(context.registered_domain)
    if rank is None:
        return None
    context.evidence["Page_Rank"] = f"Tranco rank proxy = {rank}"
    return 1 if rank < 100_000 else -1


def _feature_google_index(context: ScanContext) -> int | None:
    if not context.registered_domain:
        return None
    rank = _fetch_tranco_rank(context.registered_domain)
    if rank is not None and rank <= 10_000:
        context.evidence["Google_Index"] = (
            f"Domain rất phổ biến (Tranco rank = {rank}), coi như có hiện diện index mạnh."
        )
        return 1
    search_results = _search_bing(f"site:{context.registered_domain}")
    if search_results is None:
        if rank is not None and rank <= 100_000:
            context.evidence["Google_Index"] = (
                f"Không truy vấn được search proxy nhưng domain khá phổ biến (Tranco rank = {rank})."
            )
            return 1
        return None
    for link in search_results:
        host = urlsplit(link).hostname or ""
        if _same_registered_domain(host.lower(), context.registered_domain):
            context.evidence["Google_Index"] = "Có kết quả index trên công cụ tìm kiếm"
            return 1
    if rank is not None and rank <= 50_000:
        context.evidence["Google_Index"] = (
            f"Search proxy không trả kết quả rõ nhưng domain có Tranco rank tốt ({rank})."
        )
        return 1
    context.evidence["Google_Index"] = "Không thấy kết quả index rõ ràng"
    return -1


def _feature_links_pointing_to_page(context: ScanContext) -> int | None:
    if not context.registered_domain:
        return None
    search_results = _search_bing(f'"{context.registered_domain}"')
    if search_results is None:
        return None
    external_mentions = 0
    for link in search_results:
        host = (urlsplit(link).hostname or "").lower()
        if host and not _same_registered_domain(host, context.registered_domain):
            external_mentions += 1
    context.evidence["Links_pointing_to_page"] = f"Số kết quả tham chiếu bên ngoài = {external_mentions}"
    if external_mentions == 0:
        return -1
    if external_mentions <= 2:
        return 0
    return 1


def _feature_statistical_report(context: ScanContext) -> int | None:
    if not context.registered_domain and not context.hostname:
        return None
    indicators = _load_public_phish_indicators()
    if indicators is None:
        return None
    normalized_url = context.normalized_url.rstrip("/")
    if normalized_url in indicators["urls"]:
        context.evidence["Statistical_report"] = "URL xuất hiện trong feed phishing công khai"
        return -1
    if context.hostname in indicators["hosts"] or context.registered_domain in indicators["hosts"]:
        context.evidence["Statistical_report"] = "Hostname xuất hiện trong feed phishing công khai"
        return -1
    if context.ip_address and context.ip_address in indicators["ips"]:
        context.evidence["Statistical_report"] = "IP xuất hiện trong feed phishing công khai"
        return -1
    return 1


@lru_cache(maxsize=512)
def _fetch_tranco_rank(domain: str) -> int | None:
    if not domain:
        return None
    try:
        response = requests.get(
            f"https://tranco-list.eu/api/ranks/domain/{domain}",
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        ranks = payload.get("ranks", [])
        if not ranks:
            return None
        return int(ranks[0]["rank"])
    except Exception:
        return None


@lru_cache(maxsize=128)
def _search_bing(query: str) -> list[str] | None:
    try:
        response = requests.get(
            f"https://www.bing.com/search?q={quote_plus(query)}",
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
    except Exception:
        return None

    html = response.text
    links: list[str] = []
    if BeautifulSoup is not None:
        soup = BeautifulSoup(html, "html.parser")
        for anchor in soup.select("li.b_algo h2 a[href]"):
            href = anchor.get("href")
            if href:
                links.append(href)
    if not links:
        links = re.findall(r'<a[^>]+href="(https?://[^"]+)"', html)
    return links[:10]


@lru_cache(maxsize=1)
def _load_public_phish_indicators() -> dict[str, set[str]] | None:
    indicators = {"urls": set(), "hosts": set(), "ips": set()}
    loaded_any = False
    for feed_url in PHISH_FEED_URLS:
        try:
            response = requests.get(feed_url, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT * 2)
            response.raise_for_status()
            loaded_any = True
        except Exception:
            continue
        for raw_line in response.text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            line = line.rstrip("/")
            indicators["urls"].add(line)
            host = (urlsplit(line).hostname or "").lower()
            if host:
                indicators["hosts"].add(host)
                if _is_ip_like(host):
                    indicators["ips"].add(host)
    return indicators if loaded_any else None
