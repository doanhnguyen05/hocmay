from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
DATA_DIR = ARTIFACTS_DIR / "data"
MODEL_DIR = ARTIFACTS_DIR / "models"
REPORT_DIR = ARTIFACTS_DIR / "reports"
CACHE_DIR = ARTIFACTS_DIR / "cache"

UCI_ZIP_URL = "https://archive.ics.uci.edu/static/public/327/phishing+websites.zip"
UCI_ZIP_PATH = DATA_DIR / "phishing_websites_uci.zip"
UCI_ARFF_NAME = "Training Dataset.arff"
UCI_DOC_NAME = "Phishing Websites Features.docx"

RESULT_COLUMN = "Result"
FEATURE_COLUMNS = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
]

FEATURE_VALUE_SPACE = {
    "having_IP_Address": {-1, 1},
    "URL_Length": {-1, 0, 1},
    "Shortining_Service": {-1, 1},
    "having_At_Symbol": {-1, 1},
    "double_slash_redirecting": {-1, 1},
    "Prefix_Suffix": {-1, 1},
    "having_Sub_Domain": {-1, 0, 1},
    "SSLfinal_State": {-1, 0, 1},
    "Domain_registeration_length": {-1, 1},
    "Favicon": {-1, 1},
    "port": {-1, 1},
    "HTTPS_token": {-1, 1},
    "Request_URL": {-1, 0, 1},
    "URL_of_Anchor": {-1, 0, 1},
    "Links_in_tags": {-1, 0, 1},
    "SFH": {-1, 0, 1},
    "Submitting_to_email": {-1, 1},
    "Abnormal_URL": {-1, 1},
    "Redirect": {0, 1},
    "on_mouseover": {-1, 1},
    "RightClick": {-1, 1},
    "popUpWidnow": {-1, 1},
    "Iframe": {-1, 1},
    "age_of_domain": {-1, 1},
    "DNSRecord": {-1, 1},
    "web_traffic": {-1, 0, 1},
    "Page_Rank": {-1, 1},
    "Google_Index": {-1, 1},
    "Links_pointing_to_page": {-1, 0, 1},
    "Statistical_report": {-1, 1},
}

DEFAULT_FEATURE_DEFAULTS = {
    "having_IP_Address": 1,
    "URL_Length": 0,
    "Shortining_Service": 1,
    "having_At_Symbol": 1,
    "double_slash_redirecting": 1,
    "Prefix_Suffix": 1,
    "having_Sub_Domain": 0,
    "SSLfinal_State": 0,
    "Domain_registeration_length": 1,
    "Favicon": 1,
    "port": 1,
    "HTTPS_token": 1,
    "Request_URL": 0,
    "URL_of_Anchor": 0,
    "Links_in_tags": 0,
    "SFH": 0,
    "Submitting_to_email": 1,
    "Abnormal_URL": 1,
    "Redirect": 0,
    "on_mouseover": 1,
    "RightClick": 1,
    "popUpWidnow": 1,
    "Iframe": 1,
    "age_of_domain": 1,
    "DNSRecord": 1,
    "web_traffic": 0,
    "Page_Rank": 1,
    "Google_Index": 1,
    "Links_pointing_to_page": 0,
    "Statistical_report": 1,
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "goo.gl",
    "tinyurl.com",
    "ow.ly",
    "t.co",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "bit.do",
    "mcaf.ee",
    "rebrand.ly",
    "cutt.ly",
    "tiny.cc",
    "lnkd.in",
    "shorturl.at",
    "rb.gy",
    "qr.ae",
    "shorte.st",
}

TRUSTED_ISSUER_HINTS = {
    "digicert",
    "globalsign",
    "let's encrypt",
    "lets encrypt",
    "sectigo",
    "comodoca",
    "geotrust",
    "godaddy",
    "amazon",
    "microsoft",
    "cloudflare",
    "entrust",
}

SAFE_PORTS = {80, 443}
REQUEST_TIMEOUT = 8
MAX_HTML_BYTES = 1_000_000
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/136.0.0.0 Safari/537.36 CyberShieldAI/1.0"
)

PHISH_FEED_URLS = [
    "https://openphish.com/feed.txt",
    "https://urlhaus.abuse.ch/downloads/text_online/",
]

TRAILING_COUNTRY_CODE_SUFFIXES = {
    "ac.uk",
    "co.uk",
    "gov.uk",
    "org.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "com.br",
    "com.cn",
    "co.in",
    "com.sg",
}

FEATURE_FRIENDLY_NAMES = {
    "having_IP_Address": "dùng địa chỉ IP thay vì tên miền",
    "URL_Length": "URL quá dài",
    "Shortining_Service": "sử dụng dịch vụ rút gọn link",
    "having_At_Symbol": "có ký tự @ trong URL",
    "double_slash_redirecting": "có dấu hiệu chuyển hướng bất thường bằng //",
    "Prefix_Suffix": "tên miền có dấu gạch ngang đáng ngờ",
    "having_Sub_Domain": "có quá nhiều subdomain",
    "SSLfinal_State": "tín hiệu HTTPS/SSL không mạnh",
    "Domain_registeration_length": "thời hạn đăng ký tên miền quá ngắn",
    "Favicon": "favicon tải từ miền ngoài",
    "port": "cổng truy cập không chuẩn",
    "HTTPS_token": "chuỗi https xuất hiện bất thường trong tên miền",
    "Request_URL": "nhiều tài nguyên tải từ miền ngoài",
    "URL_of_Anchor": "anchor link bất thường hoặc rỗng",
    "Links_in_tags": "meta/script/link trỏ ra ngoài quá nhiều",
    "SFH": "form action bất thường",
    "Submitting_to_email": "có dấu hiệu gửi dữ liệu qua email",
    "Abnormal_URL": "URL bất thường so với danh tính tên miền",
    "Redirect": "có nhiều lần redirect",
    "on_mouseover": "có script thay đổi thanh trạng thái",
    "RightClick": "có dấu hiệu khóa chuột phải",
    "popUpWidnow": "có popup đáng ngờ",
    "Iframe": "có iframe ẩn hoặc lồng iframe",
    "age_of_domain": "tên miền quá mới",
    "DNSRecord": "bản ghi DNS yếu hoặc thiếu",
    "web_traffic": "mức độ phổ biến tên miền thấp",
    "Page_Rank": "độ phổ biến tổng thể của tên miền thấp",
    "Google_Index": "không thấy dấu hiệu được index",
    "Links_pointing_to_page": "ít dấu vết liên kết trỏ đến trang",
    "Statistical_report": "trùng khớp feed cảnh báo phishing công khai",
}
