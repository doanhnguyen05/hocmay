from __future__ import annotations

from cybershield_ai.config import DEFAULT_FEATURE_DEFAULTS, FEATURE_COLUMNS, FEATURE_VALUE_SPACE
from cybershield_ai.feature_extraction import (
    ScanContext,
    _feature_google_index,
    _feature_ssl_final_state,
    configure_feature_defaults,
    extract_features_from_url,
    scan_url,
)


def test_extract_features_returns_full_schema() -> None:
    configure_feature_defaults(DEFAULT_FEATURE_DEFAULTS)
    features = extract_features_from_url("http://secure-login-bank.com@hack.it/")

    assert list(features.keys()) == FEATURE_COLUMNS
    assert len(features) == 30
    for column, value in features.items():
        assert value in FEATURE_VALUE_SPACE[column]


def test_scan_url_handles_missing_scheme_and_ip_url() -> None:
    configure_feature_defaults(DEFAULT_FEATURE_DEFAULTS)
    result = scan_url("125.98.3.123/fake.html")

    assert result["features"]["having_IP_Address"] == -1
    assert result["features"]["URL_Length"] in FEATURE_VALUE_SPACE["URL_Length"]
    assert isinstance(result["warnings"], list)
    assert "risk_category" in result
    assert "risk_category_label" in result
    assert "risk_signals" in result


def test_scan_url_survives_non_resolving_host() -> None:
    configure_feature_defaults(DEFAULT_FEATURE_DEFAULTS)
    result = scan_url("http://this-domain-should-not-exist-12345.example.invalid/login")

    assert len(result["features"]) == 30
    assert all(result["features"][column] in FEATURE_VALUE_SPACE[column] for column in FEATURE_COLUMNS)
    assert isinstance(result["risk_summary"], str)


def test_sslfinal_state_accepts_trusted_valid_https_even_when_expiry_is_near() -> None:
    context = ScanContext(
        raw_url="https://www.facebook.com/",
        normalized_url="https://www.facebook.com/",
        hostname="www.facebook.com",
        registered_domain="facebook.com",
        subdomain="www",
        suffix="com",
        parsed=object(),
        ssl_info={"valid": True, "issuer_trusted": True, "days_remaining": 7},
    )
    context.parsed = type("Parsed", (), {"scheme": "https"})()

    value = _feature_ssl_final_state(context)

    assert value == 1
    assert "HTTPS hợp lệ" in context.evidence["SSLfinal_State"]


def test_google_index_uses_popularity_fallback_for_large_domains(monkeypatch) -> None:
    context = ScanContext(
        raw_url="https://www.facebook.com/",
        normalized_url="https://www.facebook.com/",
        hostname="www.facebook.com",
        registered_domain="facebook.com",
        subdomain="www",
        suffix="com",
        parsed=type("Parsed", (), {"scheme": "https"})(),
    )

    monkeypatch.setattr("cybershield_ai.feature_extraction._fetch_tranco_rank", lambda domain: 4)
    monkeypatch.setattr("cybershield_ai.feature_extraction._search_bing", lambda query: [])

    value = _feature_google_index(context)

    assert value == 1
    assert "Tranco rank" in context.evidence["Google_Index"]
