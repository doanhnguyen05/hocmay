"""Public URL scanning API for CyberShield AI.

This module keeps the stable public entry points while implementation details
live in focused modules:

- ``url_features``: URL morphology and domain parsing.
- ``html_features``: DOM and HTML behavior features.
- ``network_clients``: HTTP, DNS and live context hydration.
- ``whois_ssl``: WHOIS, SSL and domain-age features.
- ``reputation``: traffic, search-index and phishing-feed features.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from .config import DEFAULT_FEATURE_DEFAULTS, FEATURE_COLUMNS, FEATURE_VALUE_SPACE
from .html_features import (
    _feature_favicon,
    _feature_iframe,
    _feature_links_in_tags,
    _feature_on_mouseover,
    _feature_popup_window,
    _feature_request_url,
    _feature_right_click,
    _feature_sfh,
    _feature_submitting_to_email,
    _feature_url_of_anchor,
)
from .network_clients import _hydrate_live_context
from .reputation import (
    _fetch_tranco_rank,
    _feature_google_index,
    _feature_links_pointing_to_page,
    _feature_page_rank,
    _feature_statistical_report,
    _feature_web_traffic,
    _load_public_phish_indicators,
    _search_bing,
)
from .risk_tagging import infer_risk_category
from .scan_context import ScanContext
from .url_features import (
    _feature_at_symbol,
    _feature_double_slash_redirecting,
    _feature_https_token,
    _feature_ip_address,
    _feature_port,
    _feature_prefix_suffix,
    _feature_redirect,
    _feature_shortener,
    _feature_subdomain,
    _feature_url_length,
    _normalize_url,
    _split_domain,
)
from .whois_ssl import (
    _feature_abnormal_url,
    _feature_age_of_domain,
    _feature_dns_record,
    _feature_domain_registration_length,
    _feature_ssl_final_state,
)

_runtime_feature_defaults = DEFAULT_FEATURE_DEFAULTS.copy()


def configure_feature_defaults(defaults: dict[str, int] | None) -> None:
    """Update runtime fallback values for live feature extraction."""
    global _runtime_feature_defaults
    if defaults:
        _runtime_feature_defaults = {**DEFAULT_FEATURE_DEFAULTS, **{k: int(v) for k, v in defaults.items()}}


def extract_features_from_url(url: str, feature_defaults: dict[str, int] | None = None) -> dict[str, int]:
    """Return the ordered 30-feature UCI vector for a URL."""
    return scan_url(url, feature_defaults=feature_defaults)["features"]


def scan_url(url: str, feature_defaults: dict[str, int] | None = None) -> dict[str, Any]:
    """Scan a URL end-to-end and return features, evidence and risk tags."""
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

    features: dict[str, int] = {
        "having_IP_Address": _resolve_feature("having_IP_Address", _feature_ip_address(context), defaults, context),
        "URL_Length": _resolve_feature("URL_Length", _feature_url_length(context), defaults, context),
        "Shortining_Service": _resolve_feature("Shortining_Service", _feature_shortener(context), defaults, context),
        "having_At_Symbol": _resolve_feature("having_At_Symbol", _feature_at_symbol(context), defaults, context),
        "double_slash_redirecting": _resolve_feature(
            "double_slash_redirecting",
            _feature_double_slash_redirecting(context),
            defaults,
            context,
        ),
        "Prefix_Suffix": _resolve_feature("Prefix_Suffix", _feature_prefix_suffix(context), defaults, context),
        "having_Sub_Domain": _resolve_feature("having_Sub_Domain", _feature_subdomain(context), defaults, context),
        "SSLfinal_State": _resolve_feature("SSLfinal_State", _feature_ssl_final_state(context), defaults, context),
        "Domain_registeration_length": _resolve_feature(
            "Domain_registeration_length",
            _feature_domain_registration_length(context),
            defaults,
            context,
        ),
        "Favicon": _resolve_feature("Favicon", _feature_favicon(context), defaults, context),
        "port": _resolve_feature("port", _feature_port(context), defaults, context),
        "HTTPS_token": _resolve_feature("HTTPS_token", _feature_https_token(context), defaults, context),
        "Request_URL": _resolve_feature("Request_URL", _feature_request_url(context), defaults, context),
        "URL_of_Anchor": _resolve_feature("URL_of_Anchor", _feature_url_of_anchor(context), defaults, context),
        "Links_in_tags": _resolve_feature("Links_in_tags", _feature_links_in_tags(context), defaults, context),
        "SFH": _resolve_feature("SFH", _feature_sfh(context), defaults, context),
        "Submitting_to_email": _resolve_feature(
            "Submitting_to_email",
            _feature_submitting_to_email(context),
            defaults,
            context,
        ),
        "Abnormal_URL": _resolve_feature("Abnormal_URL", _feature_abnormal_url(context), defaults, context),
        "Redirect": _resolve_feature("Redirect", _feature_redirect(context), defaults, context),
        "on_mouseover": _resolve_feature("on_mouseover", _feature_on_mouseover(context), defaults, context),
        "RightClick": _resolve_feature("RightClick", _feature_right_click(context), defaults, context),
        "popUpWidnow": _resolve_feature("popUpWidnow", _feature_popup_window(context), defaults, context),
        "Iframe": _resolve_feature("Iframe", _feature_iframe(context), defaults, context),
        "age_of_domain": _resolve_feature("age_of_domain", _feature_age_of_domain(context), defaults, context),
        "DNSRecord": _resolve_feature("DNSRecord", _feature_dns_record(context), defaults, context),
        "web_traffic": _resolve_feature("web_traffic", _feature_web_traffic(context), defaults, context),
        "Page_Rank": _resolve_feature("Page_Rank", _feature_page_rank(context), defaults, context),
        "Google_Index": _resolve_feature("Google_Index", _feature_google_index(context), defaults, context),
        "Links_pointing_to_page": _resolve_feature(
            "Links_pointing_to_page",
            _feature_links_pointing_to_page(context),
            defaults,
            context,
        ),
        "Statistical_report": _resolve_feature(
            "Statistical_report",
            _feature_statistical_report(context),
            defaults,
            context,
        ),
    }

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
