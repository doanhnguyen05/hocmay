"""Tải và tiền xử lý bộ dữ liệu UCI Phishing Websites.

Module này cung cấp các hàm để tải bộ dữ liệu phishing từ UCI Machine
Learning Repository, phân tích tệp ARFF, và chuẩn bị dữ liệu huấn luyện
dưới dạng ``DatasetBundle``. Ngoài ra còn hỗ trợ tính toán giá trị mặc
định cho các đặc trưng dựa trên phân phối mode của tập huấn luyện.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.request import urlopen

import pandas as pd

from .config import (
    ARTIFACTS_DIR,
    CACHE_DIR,
    DATA_DIR,
    DEFAULT_FEATURE_DEFAULTS,
    FEATURE_COLUMNS,
    MODEL_DIR,
    REPORT_DIR,
    RESULT_COLUMN,
    UCI_ARFF_NAME,
    UCI_ZIP_PATH,
    UCI_ZIP_URL,
)


@dataclass(slots=True)
class DatasetBundle:
    """Gói dữ liệu chứa toàn bộ thông tin cần thiết sau khi nạp dataset.

    Attributes:
        dataframe: DataFrame gốc chứa tất cả các cột (đặc trưng + nhãn).
        X: DataFrame chỉ chứa 30 cột đặc trưng UCI đã ép kiểu ``int``.
        y: Series nhãn nhị phân ``is_phishing`` (1 = phishing, 0 = hợp lệ).
        raw_target: Series nhãn gốc từ cột *Result* trước khi chuyển đổi
            (giá trị -1 = phishing, 1 = hợp lệ trong bộ UCI ban đầu).
    """

    dataframe: pd.DataFrame
    X: pd.DataFrame
    y: pd.Series
    raw_target: pd.Series


def ensure_project_dirs() -> None:
    """Tạo toàn bộ thư mục dự án nếu chưa tồn tại.

    Các thư mục được tạo bao gồm: ``artifacts/``, ``data/``, ``models/``,
    ``reports/``, và ``cache/``. Hàm này an toàn khi gọi nhiều lần
    (``exist_ok=True``).
    """
    for path in (ARTIFACTS_DIR, DATA_DIR, MODEL_DIR, REPORT_DIR, CACHE_DIR):
        path.mkdir(parents=True, exist_ok=True)


def download_uci_dataset(force: bool = False) -> Path:
    """Tải tệp ZIP bộ dữ liệu UCI Phishing Websites về thư mục ``data/``.

    Nếu tệp đã tồn tại và *force* là ``False``, hàm sẽ bỏ qua việc tải
    lại và trả về đường dẫn hiện có.

    Args:
        force: Nếu ``True``, luôn tải lại tệp ngay cả khi đã có sẵn.

    Returns:
        Đường dẫn ``Path`` tới tệp ZIP đã tải.

    Raises:
        urllib.error.URLError: Khi không kết nối được tới máy chủ UCI.
    """
    ensure_project_dirs()
    if UCI_ZIP_PATH.exists() and not force:
        return UCI_ZIP_PATH

    with urlopen(UCI_ZIP_URL, timeout=30) as response:
        payload = response.read()
    UCI_ZIP_PATH.write_bytes(payload)
    return UCI_ZIP_PATH


def _parse_arff_lines(lines: Iterable[str]) -> pd.DataFrame:
    """Phân tích nội dung ARFF dạng text thành DataFrame.

    Hàm này đọc các dòng text theo chuẩn ARFF (Attribute-Relation File
    Format), trích xuất tên thuộc tính từ các khai báo ``@attribute`` và
    chuyển vùng ``@data`` thành danh sách bản ghi số nguyên.

    Args:
        lines: Iterator hoặc danh sách các dòng text từ tệp ARFF.

    Returns:
        DataFrame với các cột là tên thuộc tính ARFF và mỗi hàng là
        một bản ghi dữ liệu (tất cả giá trị đều là ``int``).
    """
    attributes: list[str] = []
    records: list[list[int]] = []
    in_data = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("%"):
            continue

        lowered = line.lower()
        if lowered.startswith("@attribute"):
            _, attr_name, _ = line.split(maxsplit=2)
            attributes.append(attr_name)
            continue

        if lowered == "@data":
            in_data = True
            continue

        if in_data:
            records.append([int(token.strip()) for token in line.split(",")])

    return pd.DataFrame(records, columns=attributes)


def load_uci_dataset(force_download: bool = False) -> DatasetBundle:
    """Tải, giải nén và phân tích bộ dữ liệu UCI Phishing Websites.

    Quy trình: tải tệp ZIP (nếu cần) → giải nén tệp ARFF → phân tích
    ARFF thành DataFrame → tách nhãn ``is_phishing`` và ma trận đặc trưng.

    Args:
        force_download: Nếu ``True``, tải lại tệp ZIP ngay cả khi đã có.

    Returns:
        ``DatasetBundle`` chứa DataFrame gốc, ma trận đặc trưng *X*,
        nhãn nhị phân *y*, và nhãn gốc *raw_target*.
    """
    zip_path = download_uci_dataset(force=force_download)
    with zipfile.ZipFile(zip_path) as archive:
        with archive.open(UCI_ARFF_NAME) as handle:
            text_stream = io.TextIOWrapper(handle, encoding="utf-8", errors="ignore")
            dataframe = _parse_arff_lines(text_stream)

    raw_target = dataframe[RESULT_COLUMN].astype(int)
    y = (raw_target == -1).astype(int).rename("is_phishing")
    X = dataframe[FEATURE_COLUMNS].astype(int)
    return DatasetBundle(dataframe=dataframe, X=X, y=y, raw_target=raw_target)


def compute_feature_defaults(X_train: pd.DataFrame) -> dict[str, int]:
    """Tính giá trị mặc định cho mỗi đặc trưng dựa trên mode của tập huấn luyện.

    Bắt đầu từ bảng ``DEFAULT_FEATURE_DEFAULTS`` trong ``config``, sau đó
    ghi đè bằng mode (giá trị xuất hiện nhiều nhất) tính trên *X_train*.
    Giá trị này được dùng làm fallback khi trích xuất đặc trưng live thất bại.

    Args:
        X_train: DataFrame chứa 30 cột đặc trưng của tập huấn luyện.

    Returns:
        Dict ánh xạ tên đặc trưng → giá trị mặc định (``int``).
    """
    defaults = DEFAULT_FEATURE_DEFAULTS.copy()
    modes = X_train.mode(dropna=True)
    if not modes.empty:
        mode_row = modes.iloc[0]
        for column in FEATURE_COLUMNS:
            defaults[column] = int(mode_row[column])
    return defaults
