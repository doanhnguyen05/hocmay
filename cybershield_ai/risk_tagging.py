from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit

RISKY_FILE_EXTENSIONS = {
    ".exe",
    ".msi",
    ".apk",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".jar",
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".dll",
    ".vbs",
    ".ps1",
}

BRAND_KEYWORDS = {
    "paypal",
    "microsoft",
    "office365",
    "outlook",
    "google",
    "gmail",
    "apple",
    "icloud",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "telegram",
    "coinbase",
    "binance",
    "vietcombank",
    "techcombank",
    "mbbank",
    "agribank",
    "sacombank",
    "bidv",
}

CREDENTIAL_KEYWORDS = {
    "login",
    "log in",
    "signin",
    "sign in",
    "verify",
    "verification",
    "password",
    "passcode",
    "otp",
    "account",
    "unlock",
    "secure",
    "bank",
    "auth",
    "sso",
}

SCAM_KEYWORDS = {
    "payment",
    "invoice",
    "refund",
    "wallet",
    "crypto",
    "gift",
    "claim",
    "reward",
    "bonus",
    "prize",
    "airdrop",
    "deposit",
    "withdraw",
    "checkout",
    "card",
}

DOWNLOAD_KEYWORDS = {
    "download",
    "setup",
    "installer",
    "update",
    "patch",
    "install",
    "file",
    "open",
    "run",
}

CATEGORY_LABELS = {
    "credential_phishing": "Credential Phishing",
    "malware_delivery": "Malware Delivery",
    "scam_fraud": "Scam / Fraud",
    "brand_impersonation": "Brand Impersonation",
    "suspicious_redirect_obfuscation": "Suspicious Redirect / Obfuscation",
    "unknown_suspicious": "Unknown Suspicious",
    "low_risk": "Low Risk / Chưa rõ kịch bản",
}

CATEGORY_SUMMARIES = {
    "credential_phishing": "Nghiêng về kịch bản đánh cắp tài khoản hoặc thông tin đăng nhập.",
    "malware_delivery": "Nghiêng về kịch bản phát tán mã độc hoặc tập tin tải xuống nguy hiểm.",
    "scam_fraud": "Nghiêng về kịch bản lừa đảo thanh toán, thưởng, hoàn tiền hoặc ví điện tử.",
    "brand_impersonation": "Nghiêng về kịch bản giả mạo thương hiệu để tạo lòng tin giả.",
    "suspicious_redirect_obfuscation": "Nghiêng về kịch bản che giấu URL, chuyển hướng hoặc làm rối địa chỉ truy cập.",
    "unknown_suspicious": "Có nhiều tín hiệu đáng ngờ nhưng chưa đủ chắc để gắn một kiểu tấn công cụ thể.",
    "low_risk": "Chưa thấy kịch bản tấn công nổi bật ngoài kết quả phân loại rủi ro tổng quát.",
}

PASSWORD_FIELD_PATTERN = re.compile(
    r'type\s*=\s*["\']password["\']|name\s*=\s*["\'](?:pass|password|passwd)["\']',
    re.IGNORECASE,
)
PAYMENT_FIELD_PATTERN = re.compile(
    r'card(number)?|cvv|cvc|expiry|expir|iban|swift|wallet|credit\s*card',
    re.IGNORECASE,
)
DOWNLOAD_LINK_PATTERN = re.compile(
    r'href\s*=\s*["\'][^"\']+\.(?:exe|msi|apk|bat|cmd|scr|js|jar|zip|rar|7z|iso|dll|vbs|ps1)(?:[?#][^"\']*)?["\']',
    re.IGNORECASE,
)


def infer_risk_category(
    *,
    raw_url: str,
    normalized_url: str,
    hostname: str,
    registered_domain: str,
    features: Mapping[str, int],
    html: str = "",
    response_headers: Mapping[str, str] | None = None,
    redirect_count: int = 0,
) -> dict[str, Any]:
    response_headers = {str(key).lower(): str(value) for key, value in (response_headers or {}).items()}
    scores: dict[str, int] = defaultdict(int)
    signals: dict[str, list[str]] = defaultdict(list)

    decoded_url = unquote(normalized_url).lower()
    html_lower = html.lower()
    combined_text = f"{decoded_url} {html_lower}"
    path_lower = (urlsplit(normalized_url).path or "").lower()
    query_lower = (urlsplit(normalized_url).query or "").lower()
    disposition = (response_headers.get("content-disposition") or "").lower()
    content_type = (response_headers.get("content-type") or "").lower()

    def add(category: str, points: int, signal: str) -> None:
        scores[category] += points
        if signal not in signals[category]:
            signals[category].append(signal)

    brand_hits = sorted(
        {
            brand
            for brand in BRAND_KEYWORDS
            if brand in combined_text and brand not in (registered_domain or "").lower()
        }
    )
    credential_hits = sorted({keyword for keyword in CREDENTIAL_KEYWORDS if keyword in combined_text})
    scam_hits = sorted({keyword for keyword in SCAM_KEYWORDS if keyword in combined_text})
    download_hits = sorted({keyword for keyword in DOWNLOAD_KEYWORDS if keyword in combined_text})

    if brand_hits:
        add("brand_impersonation", 4, f"Nhắc đến thương hiệu không khớp tên miền: {', '.join(brand_hits[:3])}.")
        if features.get("Prefix_Suffix") == -1:
            add("brand_impersonation", 1, "Tên miền có dấu gạch ngang dễ gây nhầm là domain chính hãng.")
        if features.get("having_Sub_Domain", 1) <= 0:
            add("brand_impersonation", 1, "Tên miền có cấu trúc subdomain dễ dùng để giả mạo thương hiệu.")

    if PASSWORD_FIELD_PATTERN.search(html_lower):
        add("credential_phishing", 4, "Trang có trường nhập mật khẩu hoặc biểu mẫu đăng nhập.")
    if credential_hits:
        add("credential_phishing", min(4, 1 + len(credential_hits)), f"Từ khóa đăng nhập/xác minh xuất hiện: {', '.join(credential_hits[:4])}.")
    if features.get("SFH") in {-1, 0}:
        add("credential_phishing", 1, "Biểu mẫu gửi dữ liệu có dấu hiệu bất thường.")
    if features.get("Submitting_to_email") == -1:
        add("credential_phishing", 2, "Trang có dấu hiệu gửi thông tin biểu mẫu qua email.")

    if _has_risky_extension(path_lower) or _has_risky_extension(query_lower):
        add("malware_delivery", 5, "URL chứa đuôi tập tin thường gắn với mã độc hoặc bộ cài.")
    if DOWNLOAD_LINK_PATTERN.search(html_lower):
        add("malware_delivery", 4, "Trang chứa liên kết tải xuống tệp thực thi hoặc tệp nén đáng ngờ.")
    if "attachment" in disposition:
        add("malware_delivery", 3, "Máy chủ trả về nội dung dạng file đính kèm để tải xuống.")
    if any(indicator in content_type for indicator in ["application/octet-stream", "application/x-msdownload", "application/java-archive"]):
        add("malware_delivery", 3, "Kiểu nội dung phản hồi phù hợp với tập tin thực thi hoặc nhị phân.")
    if download_hits:
        add("malware_delivery", min(3, len(download_hits)), f"Từ khóa tải file/cài đặt xuất hiện: {', '.join(download_hits[:4])}.")

    if scam_hits:
        add("scam_fraud", min(4, 1 + len(scam_hits)), f"Từ khóa thanh toán/lợi ích tài chính xuất hiện: {', '.join(scam_hits[:4])}.")
    if PAYMENT_FIELD_PATTERN.search(html_lower):
        add("scam_fraud", 4, "Trang có trường nhập thông tin thẻ hoặc ví điện tử.")

    if features.get("having_At_Symbol") == -1:
        add("suspicious_redirect_obfuscation", 2, "URL có ký tự @ để che giấu hostname thật.")
    if features.get("double_slash_redirecting") == -1:
        add("suspicious_redirect_obfuscation", 2, "URL có dấu hiệu chèn // bất thường để chuyển hướng.")
    if features.get("Shortining_Service") == -1:
        add("suspicious_redirect_obfuscation", 2, "Dùng dịch vụ rút gọn link để che URL đích.")
    if features.get("having_IP_Address") == -1:
        add("suspicious_redirect_obfuscation", 2, "Dùng địa chỉ IP trực tiếp thay cho tên miền.")
    if features.get("Redirect") == 1 or redirect_count > 1:
        add("suspicious_redirect_obfuscation", 1, "Chuỗi chuyển hướng nhiều bước.")
    if features.get("HTTPS_token") == -1:
        add("suspicious_redirect_obfuscation", 1, "Chèn token 'https' trong hostname để gây nhầm lẫn.")
    if features.get("having_Sub_Domain", 1) <= 0:
        add("suspicious_redirect_obfuscation", 1, "Hostname có nhiều subdomain hoặc cấu trúc bất thường.")
    if features.get("URL_Length", 1) <= 0:
        add("suspicious_redirect_obfuscation", 1, "URL dài bất thường, dễ che giấu mục tiêu thật.")

    suspicious_feature_count = sum(
        1
        for name, value in features.items()
        if (name == "Redirect" and value == 1)
        or (name != "Redirect" and value == -1)
    )

    primary_category, primary_score = _pick_primary_category(scores)
    if primary_score < 4:
        if scores["suspicious_redirect_obfuscation"] >= 3:
            primary_category = "suspicious_redirect_obfuscation"
        elif suspicious_feature_count >= 4:
            primary_category = "unknown_suspicious"
            signals[primary_category].append(
                f"Có {suspicious_feature_count} đặc trưng phishing ở trạng thái xấu hoặc đáng ngờ."
            )
        else:
            primary_category = "low_risk"

    if primary_category == "credential_phishing" and brand_hits:
        add("credential_phishing", 1, "Có dấu hiệu giả mạo thương hiệu để đánh cắp thông tin đăng nhập.")
    if primary_category == "brand_impersonation" and credential_hits:
        add("brand_impersonation", 1, "Trang vừa nhắc thương hiệu vừa có từ khóa đăng nhập/xác minh.")

    top_signals = signals.get(primary_category, [])[:4]
    return {
        "risk_category": primary_category,
        "risk_category_label": CATEGORY_LABELS[primary_category],
        "risk_summary": CATEGORY_SUMMARIES[primary_category],
        "risk_signals": top_signals,
        "risk_scores": dict(scores),
    }


def _has_risky_extension(text: str) -> bool:
    return any(extension in text for extension in RISKY_FILE_EXTENSIONS)


def _pick_primary_category(scores: Mapping[str, int]) -> tuple[str, int]:
    priority = [
        "malware_delivery",
        "credential_phishing",
        "scam_fraud",
        "brand_impersonation",
        "suspicious_redirect_obfuscation",
    ]
    best_category = "low_risk"
    best_score = 0
    for category in priority:
        score = int(scores.get(category, 0))
        if score > best_score:
            best_category = category
            best_score = score
    return best_category, best_score
