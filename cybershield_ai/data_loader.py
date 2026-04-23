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
    dataframe: pd.DataFrame
    X: pd.DataFrame
    y: pd.Series
    raw_target: pd.Series


def ensure_project_dirs() -> None:
    for path in (ARTIFACTS_DIR, DATA_DIR, MODEL_DIR, REPORT_DIR, CACHE_DIR):
        path.mkdir(parents=True, exist_ok=True)


def download_uci_dataset(force: bool = False) -> Path:
    ensure_project_dirs()
    if UCI_ZIP_PATH.exists() and not force:
        return UCI_ZIP_PATH

    with urlopen(UCI_ZIP_URL, timeout=30) as response:
        payload = response.read()
    UCI_ZIP_PATH.write_bytes(payload)
    return UCI_ZIP_PATH


def _parse_arff_lines(lines: Iterable[str]) -> pd.DataFrame:
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
    defaults = DEFAULT_FEATURE_DEFAULTS.copy()
    modes = X_train.mode(dropna=True)
    if not modes.empty:
        mode_row = modes.iloc[0]
        for column in FEATURE_COLUMNS:
            defaults[column] = int(mode_row[column])
    return defaults
