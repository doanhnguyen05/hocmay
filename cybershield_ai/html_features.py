from __future__ import annotations

import re

from .scan_context import ScanContext
from .url_features import _is_external_reference

WINDOWS_STATUS_PATTERN = re.compile(r"window\.status|status\s*=", re.IGNORECASE)
RIGHT_CLICK_PATTERN = re.compile(r"event\.button\s*==\s*2|contextmenu", re.IGNORECASE)
MAIL_PATTERN = re.compile(r"mailto:|mail\(", re.IGNORECASE)


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
