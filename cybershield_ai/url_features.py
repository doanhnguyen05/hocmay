from __future__ import annotations

import ipaddress
import re
from urllib.parse import urljoin, urlsplit

from .config import SAFE_PORTS, SHORTENER_DOMAINS, TRAILING_COUNTRY_CODE_SUFFIXES
from .scan_context import ScanContext

try:
    import tldextract
except ImportError:  # pragma: no cover
    tldextract = None
    _TLD_EXTRACTOR = None
else:
    _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

HEX_IP_PATTERN = re.compile(r"^(0x[0-9a-fA-F]+\.){3}0x[0-9a-fA-F]+$")


def _normalize_url(url: str) -> str:
    cleaned = (url or "").strip()
    if not cleaned:
        return "http://"
    if cleaned.startswith("//"):
        cleaned = "http:" + cleaned
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = "http://" + cleaned
    return cleaned


def _split_domain(hostname: str) -> tuple[str, str, str]:
    if not hostname:
        return "", "", ""
    if _is_ip_like(hostname):
        return hostname, "", ""

    if _TLD_EXTRACTOR is not None:
        try:
            extracted = _TLD_EXTRACTOR(hostname)
            registered_domain = ".".join(part for part in [extracted.domain, extracted.suffix] if part)
            if registered_domain:
                return registered_domain.lower(), extracted.subdomain.lower(), extracted.suffix.lower()
        except Exception:
            pass

    labels = [label for label in hostname.split(".") if label]
    if len(labels) < 2:
        return hostname, "", ""

    trailing = ".".join(labels[-2:])
    if len(labels) >= 3 and trailing in TRAILING_COUNTRY_CODE_SUFFIXES:
        registered = ".".join(labels[-3:])
        subdomain = ".".join(labels[:-3])
        suffix = trailing
    else:
        registered = ".".join(labels[-2:])
        subdomain = ".".join(labels[:-2])
        suffix = labels[-1]
    return registered.lower(), subdomain.lower(), suffix.lower()


def _is_external_reference(candidate: str, context: ScanContext) -> bool:
    absolute = urljoin(context.final_url or context.normalized_url, candidate)
    parsed = urlsplit(absolute)
    if not parsed.hostname:
        return False
    candidate_domain, _, _ = _split_domain(parsed.hostname.lower())
    target_domain = context.registered_domain or context.hostname
    return not _same_registered_domain(candidate_domain or parsed.hostname.lower(), target_domain)


def _same_registered_domain(left: str, right: str) -> bool:
    if not left or not right:
        return False
    left_reg, _, _ = _split_domain(left)
    right_reg, _, _ = _split_domain(right)
    return (left_reg or left) == (right_reg or right)


def _is_ip_like(hostname: str) -> bool:
    if not hostname:
        return False
    if HEX_IP_PATTERN.match(hostname):
        return True
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _feature_ip_address(context: ScanContext) -> int:
    if _is_ip_like(context.hostname):
        context.evidence["having_IP_Address"] = f"Hostname đang là IP: {context.hostname}"
        return -1
    return 1


def _feature_url_length(context: ScanContext) -> int:
    length = len(context.normalized_url)
    context.evidence["URL_Length"] = f"Độ dài URL = {length}"
    if length < 54:
        return 1
    if length <= 75:
        return 0
    return -1


def _feature_shortener(context: ScanContext) -> int:
    host = context.registered_domain or context.hostname
    if host in SHORTENER_DOMAINS:
        context.evidence["Shortining_Service"] = f"Phát hiện shortener: {host}"
        return -1
    return 1


def _feature_at_symbol(context: ScanContext) -> int:
    if "@" in context.raw_url or "@" in context.normalized_url:
        context.evidence["having_At_Symbol"] = "Phát hiện ký tự @ trong URL"
        return -1
    return 1


def _feature_double_slash_redirecting(context: ScanContext) -> int:
    last_double_slash = context.normalized_url.rfind("//")
    if last_double_slash > 7:
        context.evidence["double_slash_redirecting"] = f"Vị trí '//' cuối = {last_double_slash}"
        return -1
    return 1


def _feature_prefix_suffix(context: ScanContext) -> int:
    core = context.registered_domain.split(".")[0] if context.registered_domain else context.hostname
    if "-" in core:
        context.evidence["Prefix_Suffix"] = f"Tên miền có dấu '-': {core}"
        return -1
    return 1


def _feature_subdomain(context: ScanContext) -> int:
    labels = [label for label in context.subdomain.split(".") if label and label != "www"]
    count = len(labels)
    context.evidence["having_Sub_Domain"] = f"Số subdomain = {count}"
    if count == 0:
        return 1
    if count == 1:
        return 0
    return -1


def _feature_port(context: ScanContext) -> int:
    port = context.parsed.port
    if port is None:
        return 1
    context.evidence["port"] = f"Cổng truy cập = {port}"
    return 1 if port in SAFE_PORTS else -1


def _feature_https_token(context: ScanContext) -> int:
    host = context.hostname or ""
    if "https" in host and context.parsed.scheme != "https":
        context.evidence["HTTPS_token"] = f"Token 'https' trong hostname: {host}"
        return -1
    if "https" in host and host.count("https") >= 1 and not host.startswith("https"):
        context.evidence["HTTPS_token"] = f"Token 'https' bất thường trong hostname: {host}"
        return -1
    return 1


def _feature_redirect(context: ScanContext) -> int:
    context.evidence["Redirect"] = f"Số lần redirect = {context.redirect_count}"
    return 0 if context.redirect_count <= 1 else 1
