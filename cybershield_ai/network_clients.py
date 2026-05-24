from __future__ import annotations

import socket
from functools import lru_cache

import requests
import urllib3

from .config import MAX_HTML_BYTES, REQUEST_TIMEOUT, USER_AGENT
from .scan_context import ScanContext
from .url_features import _is_ip_like
from .whois_ssl import _lookup_ssl_info, _lookup_whois

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

try:
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None
else:
    dns = dns


def _hydrate_live_context(context: ScanContext) -> None:
    if not context.hostname:
        context.warnings.append("Không tìm thấy hostname hợp lệ trong URL.")
        return

    context.dns_resolved, context.ip_address = _resolve_dns(context.hostname)
    if context.parsed.scheme in {"http", "https"}:
        try:
            response = requests.get(
                context.normalized_url,
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )
            context.response = response
            context.final_url = response.url
            context.redirect_count = len(response.history)
            content_type = response.headers.get("content-type", "")
            if "text/html" in content_type or content_type == "":
                context.html = response.text[:MAX_HTML_BYTES]
                if BeautifulSoup is not None:
                    context.soup = BeautifulSoup(context.html, "html.parser")
        except requests.RequestException as exc:
            context.warnings.append(f"Không tải được nội dung HTML: {exc}")
    if context.registered_domain:
        context.whois_record = _lookup_whois(context.registered_domain)
    if context.parsed.scheme == "https":
        port = context.parsed.port or 443
        context.ssl_info = _lookup_ssl_info(context.hostname, port)


@lru_cache(maxsize=512)
def _resolve_dns(hostname: str) -> tuple[bool | None, str | None]:
    if not hostname:
        return None, None
    if _is_ip_like(hostname):
        return True, hostname

    if dns is not None:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = REQUEST_TIMEOUT
        resolver.timeout = REQUEST_TIMEOUT
        try:
            answers = resolver.resolve(hostname, "A")
            first = answers[0].to_text() if answers else None
            return True, first
        except Exception:
            pass

    try:
        return True, socket.gethostbyname(hostname)
    except Exception:
        return False, None
