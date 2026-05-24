from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import requests


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
