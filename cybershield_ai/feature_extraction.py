from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import quote_plus, urljoin, urlsplit

import requests
import urllib3

from .config import (
    DEFAULT_FEATURE_DEFAULTS,
    FEATURE_COLUMNS,
    FEATURE_VALUE_SPACE,
    MAX_HTML_BYTES,
    PHISH_FEED_URLS,
    REQUEST_TIMEOUT,
    SAFE_PORTS,
    SHORTENER_DOMAINS,
    TRAILING_COUNTRY_CODE_SUFFIXES,
    TRUSTED_ISSUER_HINTS,
    USER_AGENT,
)
from .risk_tagging import infer_risk_category

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - exercised in environments without bs4
    BeautifulSoup = None

try:
    import tldextract
except ImportError:  # pragma: no cover - exercised in environments without tldextract
    tldextract = None
    _TLD_EXTRACTOR = None
else:
    # Use the bundled snapshot instead of live suffix-list updates so scans stay
    # stable in restricted/offline environments and avoid cache-lock hiccups.
    _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

try:
    import whois
except ImportError:  # pragma: no cover - exercised in environments without python-whois
    whois = None

try:
    import dns.resolver
except ImportError:  # pragma: no cover - exercised in environments without dnspython
    dns = None
else:
    dns = dns


HEX_IP_PATTERN = re.compile(r"^(0x[0-9a-fA-F]+\.){3}0x[0-9a-fA-F]+$")
WINDOWS_STATUS_PATTERN = re.compile(r"window\.status|status\s*=", re.IGNORECASE)
RIGHT_CLICK_PATTERN = re.compile(r"event\.button\s*==\s*2|contextmenu", re.IGNORECASE)
MAIL_PATTERN = re.compile(r"mailto:|mail\(", re.IGNORECASE)

_runtime_feature_defaults = DEFAULT_FEATURE_DEFAULTS.copy()


@dataclass(slots=True)
class ScanContext:
    raw_url: str
    normalized_url: str
    hostname: str
    registered_domain: str
    subdomain: str
    suffix: str
    parsed: Any
    response: requests.Response | None = None
    final_url: str | None = None
    html: str = ""
    soup: Any = None
    redirect_count: int = 0
    warnings: list[str] = field(default_factory=list)
    fallback_features: list[str] = field(default_factory=list)
    evidence: dict[str, str] = field(default_factory=dict)
    dns_resolved: bool | None = None
    ip_address: str | None = None
    whois_record: Any = None
    ssl_info: dict[str, Any] | None = None


def configure_feature_defaults(defaults: dict[str, int] | None) -> None:
    global _runtime_feature_defaults
    if defaults:
        _runtime_feature_defaults = {**DEFAULT_FEATURE_DEFAULTS, **{k: int(v) for k, v in defaults.items()}}


def extract_features_from_url(url: str, feature_defaults: dict[str, int] | None = None) -> dict[str, int]:
    return scan_url(url, feature_defaults=feature_defaults)["features"]


def scan_url(url: str, feature_defaults: dict[str, int] | None = None) -> dict[str, Any]:
    defaults = {**_runtime_feature_defaults, **(feature_defaults or {})}
    normalized_url = _normalize_url(url)
    parsed = urlsplit(normalized_url)
    hostname = (parsed.hostname or "").lower()
    registered_domain, subdomain, suffix = _split_domain(hostname)

    context = ScanContext(
        raw_url=url,
        normalized_url=normalized_url,
        hostname=hostname,
        registered_domain=registered_domain,
        subdomain=subdomain,
        suffix=suffix,
        parsed=parsed,
    )

    _hydrate_live_context(context)

    features: dict[str, int] = {}
    features["having_IP_Address"] = _resolve_feature(
        "having_IP_Address",
        _feature_ip_address(context),
        defaults,
        context,
    )
    features["URL_Length"] = _resolve_feature("URL_Length", _feature_url_length(context), defaults, context)
    features["Shortining_Service"] = _resolve_feature(
        "Shortining_Service",
        _feature_shortener(context),
        defaults,
        context,
    )
    features["having_At_Symbol"] = _resolve_feature(
        "having_At_Symbol",
        _feature_at_symbol(context),
        defaults,
        context,
    )
    features["double_slash_redirecting"] = _resolve_feature(
        "double_slash_redirecting",
        _feature_double_slash_redirecting(context),
        defaults,
        context,
    )
    features["Prefix_Suffix"] = _resolve_feature(
        "Prefix_Suffix",
        _feature_prefix_suffix(context),
        defaults,
        context,
    )
    features["having_Sub_Domain"] = _resolve_feature(
        "having_Sub_Domain",
        _feature_subdomain(context),
        defaults,
        context,
    )
    features["SSLfinal_State"] = _resolve_feature(
        "SSLfinal_State",
        _feature_ssl_final_state(context),
        defaults,
        context,
    )
    features["Domain_registeration_length"] = _resolve_feature(
        "Domain_registeration_length",
        _feature_domain_registration_length(context),
        defaults,
        context,
    )
    features["Favicon"] = _resolve_feature("Favicon", _feature_favicon(context), defaults, context)
    features["port"] = _resolve_feature("port", _feature_port(context), defaults, context)
    features["HTTPS_token"] = _resolve_feature(
        "HTTPS_token",
        _feature_https_token(context),
        defaults,
        context,
    )
    features["Request_URL"] = _resolve_feature(
        "Request_URL",
        _feature_request_url(context),
        defaults,
        context,
    )
    features["URL_of_Anchor"] = _resolve_feature(
        "URL_of_Anchor",
        _feature_url_of_anchor(context),
        defaults,
        context,
    )
    features["Links_in_tags"] = _resolve_feature(
        "Links_in_tags",
        _feature_links_in_tags(context),
        defaults,
        context,
    )
    features["SFH"] = _resolve_feature("SFH", _feature_sfh(context), defaults, context)
    features["Submitting_to_email"] = _resolve_feature(
        "Submitting_to_email",
        _feature_submitting_to_email(context),
        defaults,
        context,
    )
    features["Abnormal_URL"] = _resolve_feature(
        "Abnormal_URL",
        _feature_abnormal_url(context),
        defaults,
        context,
    )
    features["Redirect"] = _resolve_feature("Redirect", _feature_redirect(context), defaults, context)
    features["on_mouseover"] = _resolve_feature(
        "on_mouseover",
        _feature_on_mouseover(context),
        defaults,
        context,
    )
    features["RightClick"] = _resolve_feature("RightClick", _feature_right_click(context), defaults, context)
    features["popUpWidnow"] = _resolve_feature(
        "popUpWidnow",
        _feature_popup_window(context),
        defaults,
        context,
    )
    features["Iframe"] = _resolve_feature("Iframe", _feature_iframe(context), defaults, context)
    features["age_of_domain"] = _resolve_feature(
        "age_of_domain",
        _feature_age_of_domain(context),
        defaults,
        context,
    )
    features["DNSRecord"] = _resolve_feature("DNSRecord", _feature_dns_record(context), defaults, context)
    features["web_traffic"] = _resolve_feature(
        "web_traffic",
        _feature_web_traffic(context),
        defaults,
        context,
    )
    features["Page_Rank"] = _resolve_feature("Page_Rank", _feature_page_rank(context), defaults, context)
    features["Google_Index"] = _resolve_feature(
        "Google_Index",
        _feature_google_index(context),
        defaults,
        context,
    )
    features["Links_pointing_to_page"] = _resolve_feature(
        "Links_pointing_to_page",
        _feature_links_pointing_to_page(context),
        defaults,
        context,
    )
    features["Statistical_report"] = _resolve_feature(
        "Statistical_report",
        _feature_statistical_report(context),
        defaults,
        context,
    )

    ordered_features = {column: int(features[column]) for column in FEATURE_COLUMNS}
    risk_assessment = infer_risk_category(
        raw_url=context.raw_url,
        normalized_url=context.normalized_url,
        hostname=context.hostname,
        registered_domain=context.registered_domain,
        features=ordered_features,
        html=context.html,
        response_headers=dict(context.response.headers) if context.response is not None else {},
        redirect_count=context.redirect_count,
    )
    return {
        "url": normalized_url,
        "features": ordered_features,
        "warnings": context.warnings,
        "fallback_features": sorted(set(context.fallback_features)),
        "evidence": context.evidence,
        "risk_category": risk_assessment["risk_category"],
        "risk_category_label": risk_assessment["risk_category_label"],
        "risk_summary": risk_assessment["risk_summary"],
        "risk_signals": risk_assessment["risk_signals"],
        "risk_scores": risk_assessment["risk_scores"],
    }


def _resolve_feature(
    name: str,
    value: int | None,
    defaults: dict[str, int],
    context: ScanContext,
) -> int:
    if value is None or int(value) not in FEATURE_VALUE_SPACE[name]:
        context.fallback_features.append(name)
        context.warnings.append(f"Feature '{name}' đã dùng fallback do thiếu dữ liệu live hoặc lỗi truy vấn.")
        return int(defaults[name])
    return int(value)


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


def _feature_ssl_final_state(context: ScanContext) -> int | None:
    if context.parsed.scheme != "https":
        context.evidence["SSLfinal_State"] = "URL không dùng HTTPS"
        return -1
    if context.ssl_info is None:
        return None
    if context.ssl_info.get("valid") and context.ssl_info.get("issuer_trusted"):
        days_remaining = int(context.ssl_info.get("days_remaining", 0))
        if days_remaining < 30:
            context.evidence["SSLfinal_State"] = (
                f"HTTPS hợp lệ, issuer đáng tin; chứng chỉ còn {days_remaining} ngày."
            )
        else:
            context.evidence["SSLfinal_State"] = "HTTPS hợp lệ với issuer đáng tin."
        return 1
    if context.ssl_info.get("valid"):
        context.evidence["SSLfinal_State"] = "HTTPS có mặt nhưng tín hiệu SSL chưa đủ mạnh"
        return 0
    context.evidence["SSLfinal_State"] = context.ssl_info.get("error", "Không xác minh được chứng chỉ")
    return 0


def _feature_domain_registration_length(context: ScanContext) -> int | None:
    expiration = _extract_whois_expiration(context.whois_record)
    if expiration is None:
        return None
    remaining_days = (expiration - _now_utc()).days
    context.evidence["Domain_registeration_length"] = f"Số ngày còn hạn đăng ký = {remaining_days}"
    return -1 if remaining_days <= 365 else 1


def _feature_favicon(context: ScanContext) -> int | None:
    if context.soup is None:
        return None
    icon = context.soup.find(
        "link",
        attrs={
            "rel": lambda value: value
            and (
                "icon" in [item.lower() for item in value]
                if isinstance(value, list)
                else "icon" in str(value).lower()
            )
        },
    )
    if icon is None:
        return 1
    href = icon.get("href")
    if href and _is_external_reference(href, context):
        context.evidence["Favicon"] = f"Favicon tải từ bên ngoài: {href}"
        return -1
    return 1


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


def _feature_request_url(context: ScanContext) -> int | None:
    if context.soup is None:
        return None
    resources = []
    for tag_name, attr_name in [("img", "src"), ("audio", "src"), ("embed", "src"), ("iframe", "src"), ("source", "src")]:
        for node in context.soup.find_all(tag_name):
            candidate = node.get(attr_name)
            if candidate:
                resources.append(candidate)
    return _ratio_to_feature(resources, context, "Request_URL", 0.22, 0.61)


def _feature_url_of_anchor(context: ScanContext) -> int | None:
    if context.soup is None:
        return None
    anchors = []
    suspicious = 0
    for anchor in context.soup.find_all("a"):
        href = (anchor.get("href") or "").strip()
        if not href:
            continue
        anchors.append(href)
        if href.startswith("#") or href.lower().startswith("javascript:") or href.lower() == "about:blank":
            suspicious += 1
        elif _is_external_reference(href, context):
            suspicious += 1
    if not anchors:
        return 1
    ratio = suspicious / len(anchors)
    context.evidence["URL_of_Anchor"] = f"Tỷ lệ anchor bất thường = {ratio:.2%}"
    if ratio < 0.31:
        return 1
    if ratio <= 0.67:
        return 0
    return -1


def _feature_links_in_tags(context: ScanContext) -> int | None:
    if context.soup is None:
        return None
    resources = []
    for tag_name, attr_name in [("meta", "content"), ("script", "src"), ("link", "href")]:
        for node in context.soup.find_all(tag_name):
            value = node.get(attr_name)
            if value and ("http" in value or value.startswith("//") or value.startswith("/")):
                resources.append(value)
    return _ratio_to_feature(resources, context, "Links_in_tags", 0.17, 0.81)


def _feature_sfh(context: ScanContext) -> int | None:
    if context.soup is None:
        return None
    forms = context.soup.find_all("form")
    if not forms:
        return 1
    for form in forms:
        action = (form.get("action") or "").strip()
        if action == "" or action.lower() == "about:blank":
            context.evidence["SFH"] = "Form action rỗng hoặc about:blank"
            return -1
        if _is_external_reference(action, context):
            context.evidence["SFH"] = f"Form action trỏ ra ngoài: {action}"
            return 0
    return 1


def _feature_submitting_to_email(context: ScanContext) -> int | None:
    if not context.html:
        return None
    if MAIL_PATTERN.search(context.html):
        context.evidence["Submitting_to_email"] = "Phát hiện mailto/mail() trong trang"
        return -1
    return 1


def _feature_abnormal_url(context: ScanContext) -> int | None:
    if context.whois_record is None:
        return 1 if context.hostname and context.hostname in context.normalized_url else None
    domain_names = _extract_whois_domain_names(context.whois_record)
    if not domain_names:
        return 1 if context.hostname and context.hostname in context.normalized_url else None
    if any(context.registered_domain in domain_name for domain_name in domain_names):
        return 1
    context.evidence["Abnormal_URL"] = "WHOIS domain không khớp với URL"
    return -1


def _feature_redirect(context: ScanContext) -> int:
    context.evidence["Redirect"] = f"Số lần redirect = {context.redirect_count}"
    return 0 if context.redirect_count <= 1 else 1


def _feature_on_mouseover(context: ScanContext) -> int | None:
    if not context.html:
        return None
    if "onmouseover" in context.html.lower() and WINDOWS_STATUS_PATTERN.search(context.html):
        context.evidence["on_mouseover"] = "Phát hiện thay đổi status bar khi hover"
        return -1
    return 1


def _feature_right_click(context: ScanContext) -> int | None:
    if not context.html:
        return None
    if RIGHT_CLICK_PATTERN.search(context.html):
        context.evidence["RightClick"] = "Phát hiện khóa chuột phải"
        return -1
    return 1


def _feature_popup_window(context: ScanContext) -> int | None:
    if not context.html:
        return None
    html_lower = context.html.lower()
    if "alert(" in html_lower or "window.open(" in html_lower:
        context.evidence["popUpWidnow"] = "Phát hiện popup Javascript"
        return -1
    return 1


def _feature_iframe(context: ScanContext) -> int | None:
    if not context.html:
        return None
    if "<iframe" in context.html.lower() or "<frame" in context.html.lower():
        context.evidence["Iframe"] = "Trang có thẻ iframe/frame"
        return -1
    return 1


def _feature_age_of_domain(context: ScanContext) -> int | None:
    creation = _extract_whois_creation(context.whois_record)
    if creation is None:
        return None
    age_days = (_now_utc() - creation).days
    context.evidence["age_of_domain"] = f"Số ngày tồn tại tên miền = {age_days}"
    return 1 if age_days >= 180 else -1


def _feature_dns_record(context: ScanContext) -> int | None:
    if context.dns_resolved is None:
        return None
    return 1 if context.dns_resolved else -1


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


def _ratio_to_feature(
    resources: list[str],
    context: ScanContext,
    evidence_key: str,
    legit_threshold: float,
    suspicious_threshold: float,
) -> int:
    if not resources:
        return 1
    external = sum(1 for resource in resources if _is_external_reference(resource, context))
    ratio = external / len(resources)
    context.evidence[evidence_key] = f"Tỷ lệ tài nguyên ngoài miền = {ratio:.2%}"
    if ratio < legit_threshold:
        return 1
    if ratio <= suspicious_threshold:
        return 0
    return -1


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


@lru_cache(maxsize=256)
def _lookup_whois(domain: str) -> Any | None:
    if whois is None or not domain:
        return None
    try:
        return whois.whois(domain)
    except Exception:
        return None


@lru_cache(maxsize=256)
def _lookup_ssl_info(hostname: str, port: int) -> dict[str, Any] | None:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secured:
                cert = secured.getpeercert()
        issuer_parts = []
        for item in cert.get("issuer", ()):
            for key, value in item:
                issuer_parts.append(f"{key}={value}")
        issuer_text = " ".join(issuer_parts).lower()
        not_after = cert.get("notAfter")
        if not_after:
            expires_at = datetime.utcfromtimestamp(ssl.cert_time_to_seconds(not_after)).replace(tzinfo=timezone.utc)
            days_remaining = (expires_at - _now_utc()).days
        else:
            days_remaining = 0
        return {
            "valid": True,
            "issuer": issuer_text,
            "issuer_trusted": any(hint in issuer_text for hint in TRUSTED_ISSUER_HINTS),
            "days_remaining": days_remaining,
        }
    except Exception as exc:
        return {"valid": False, "error": str(exc), "days_remaining": 0, "issuer_trusted": False}


def _extract_whois_domain_names(record: Any) -> list[str]:
    if record is None:
        return []
    raw = None
    if isinstance(record, dict):
        raw = record.get("domain_name")
    else:
        raw = getattr(record, "domain_name", None)
    if raw is None:
        return []
    values = raw if isinstance(raw, (list, tuple, set)) else [raw]
    return [str(value).strip().lower() for value in values if value]


def _extract_whois_creation(record: Any) -> datetime | None:
    raw = _extract_record_field(record, "creation_date")
    return _normalize_datetime(raw, pick="min")


def _extract_whois_expiration(record: Any) -> datetime | None:
    raw = _extract_record_field(record, "expiration_date")
    return _normalize_datetime(raw, pick="max")


def _extract_record_field(record: Any, field_name: str) -> Any:
    if record is None:
        return None
    if isinstance(record, dict):
        return record.get(field_name)
    return getattr(record, field_name, None)


def _normalize_datetime(value: Any, pick: str) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        normalized = [item for item in (_normalize_datetime(item, pick="min") for item in value) if item is not None]
        if not normalized:
            return None
        return min(normalized) if pick == "min" else max(normalized)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


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


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)
