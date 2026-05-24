from __future__ import annotations

import csv
import io
import time
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
import requests
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

from .config import (
    FEATURE_COLUMNS,
    MODEL_DIR,
    PHISH_FEED_URLS,
    REPORT_DIR,
    REQUEST_TIMEOUT,
    TRANCO_TOP_1M_URL,
    USER_AGENT,
)
from .feature_extraction import configure_feature_defaults, scan_url
from .modeling import save_confusion_matrix_plot, save_json

DEFAULT_MODEL_PATH = MODEL_DIR / "cybershield_ai_model.joblib"
DEFAULT_OUTPUT_DIR = REPORT_DIR / "live_benchmark"


FALLBACK_LEGITIMATE_DOMAINS = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "wikipedia.org",
    "github.com",
    "stackoverflow.com",
    "python.org",
    "scikit-learn.org",
    "pandas.pydata.org",
    "numpy.org",
    "cloudflare.com",
    "mozilla.org",
    "openai.com",
    "bbc.com",
    "cnn.com",
    "nytimes.com",
    "reuters.com",
    "paypal.com",
    "linkedin.com",
    "instagram.com",
    "netflix.com",
    "adobe.com",
    "dropbox.com",
    "salesforce.com",
    "oracle.com",
    "ibm.com",
    "nvidia.com",
    "intel.com",
    "amd.com",
    "zoom.us",
    "slack.com",
    "notion.so",
    "figma.com",
    "canva.com",
    "spotify.com",
    "shopify.com",
    "wordpress.org",
    "ubuntu.com",
    "debian.org",
    "redhat.com",
    "docker.com",
    "kubernetes.io",
    "nginx.org",
    "apache.org",
    "postgresql.org",
    "mysql.com",
    "sqlite.org",
]


def fetch_phishing_urls(count: int, random_state: int = 42) -> list[str]:
    urls: list[str] = []
    for feed_url in PHISH_FEED_URLS:
        try:
            response = requests.get(feed_url, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT * 2)
            response.raise_for_status()
        except requests.RequestException:
            continue
        for raw_line in response.text.splitlines():
            url = raw_line.strip()
            if not url or url.startswith("#"):
                continue
            parsed = urlsplit(url)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                urls.append(url.rstrip())

    unique_urls = sorted(set(urls))
    if len(unique_urls) <= count:
        return unique_urls
    return pd.Series(unique_urls).sample(count, random_state=random_state).tolist()


def fetch_legitimate_urls(count: int) -> list[str]:
    domains: list[str] = []
    try:
        response = requests.get(TRANCO_TOP_1M_URL, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT * 4)
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            with archive.open("top-1m.csv") as handle:
                text = io.TextIOWrapper(handle, encoding="utf-8", errors="ignore")
                for row in csv.reader(text):
                    if len(row) < 2:
                        continue
                    domain = row[1].strip().lower()
                    if domain and "." in domain:
                        domains.append(domain)
                    if len(domains) >= count * 4:
                        break
    except Exception:
        domains = FALLBACK_LEGITIMATE_DOMAINS.copy()

    unique_domains = list(dict.fromkeys(domains or FALLBACK_LEGITIMATE_DOMAINS))
    return [f"https://{domain}" for domain in unique_domains[:count]]


def build_live_benchmark_dataset(
    phishing_count: int = 250,
    legitimate_count: int = 250,
    random_state: int = 42,
) -> pd.DataFrame:
    phishing_urls = fetch_phishing_urls(phishing_count, random_state=random_state)
    legitimate_urls = fetch_legitimate_urls(legitimate_count)
    rows = [
        {"url": url, "label": 1, "source": "public_phishing_feed"}
        for url in phishing_urls[:phishing_count]
    ]
    rows.extend(
        {"url": url, "label": 0, "source": "tranco_top_domains"}
        for url in legitimate_urls[:legitimate_count]
    )
    return pd.DataFrame(rows).sample(frac=1.0, random_state=random_state).reset_index(drop=True)


def run_live_benchmark(
    model_path: Path = DEFAULT_MODEL_PATH,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    phishing_count: int = 250,
    legitimate_count: int = 250,
    max_urls: int | None = None,
    random_state: int = 42,
    delay_seconds: float = 0.0,
    progress_every: int = 10,
    verbose: bool = True,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    if verbose:
        print(f"Loading model: {model_path}", flush=True)
    artifact = joblib.load(model_path)
    configure_feature_defaults(artifact.get("feature_defaults"))
    threshold = float(artifact.get("decision_threshold", 0.5))
    if verbose:
        print(
            f"Building live benchmark dataset "
            f"({phishing_count} phishing + {legitimate_count} legitimate)...",
            flush=True,
        )
    dataset = build_live_benchmark_dataset(
        phishing_count=phishing_count,
        legitimate_count=legitimate_count,
        random_state=random_state,
    )
    if max_urls is not None:
        dataset = dataset.head(max_urls).copy()

    rows: list[dict[str, Any]] = []
    total = len(dataset)
    partial_path = output_dir / "live_benchmark_predictions.partial.csv"
    if verbose:
        print(f"Scanning {total} URLs with threshold={threshold:.4f}", flush=True)
    started_at = time.perf_counter()
    for position, (_, item) in enumerate(dataset.iterrows(), start=1):
        scan_result = scan_url(str(item["url"]), feature_defaults=artifact["feature_defaults"])
        feature_row = pd.DataFrame([scan_result["features"]], columns=artifact["feature_columns"])
        probability = float(artifact["model"].predict_proba(feature_row)[0, 1])
        prediction = int(probability >= threshold)
        rows.append(
            {
                "url": item["url"],
                "source": item["source"],
                "label": int(item["label"]),
                "prediction": prediction,
                "probability_phishing": probability,
                "threshold": threshold,
                "risk_category": scan_result["risk_category"],
                "warning_count": len(scan_result["warnings"]),
                "fallback_feature_count": len(scan_result["fallback_features"]),
            }
        )
        if progress_every > 0 and (position == 1 or position % progress_every == 0 or position == total):
            elapsed = time.perf_counter() - started_at
            rate = position / elapsed if elapsed > 0 else 0.0
            if verbose:
                print(
                    f"[{position}/{total}] "
                    f"label={int(item['label'])} pred={prediction} "
                    f"p={probability:.3f} fallbacks={len(scan_result['fallback_features'])} "
                    f"rate={rate:.2f} url/s",
                    flush=True,
                )
            pd.DataFrame(rows).to_csv(partial_path, index=False)
        if delay_seconds > 0 and position < total:
            time.sleep(delay_seconds)

    predictions_df = pd.DataFrame(rows)
    predictions_path = output_dir / "live_benchmark_predictions.csv"
    predictions_df.to_csv(predictions_path, index=False)

    y_true = predictions_df["label"].to_numpy(dtype=int)
    y_pred = predictions_df["prediction"].to_numpy(dtype=int)
    probabilities = predictions_df["probability_phishing"].to_numpy(dtype=float)
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    report = classification_report(
        y_true,
        y_pred,
        target_names=["legitimate", "phishing"],
        output_dict=True,
        zero_division=0,
    )
    metrics: dict[str, Any] = {
        "sample_count": int(len(predictions_df)),
        "class_counts": {
            "legitimate": int((predictions_df["label"] == 0).sum()),
            "phishing": int((predictions_df["label"] == 1).sum()),
        },
        "threshold": threshold,
        "confusion_matrix": matrix.tolist(),
        "classification_report": report,
        "predictions_path": str(predictions_path),
    }
    if len(np.unique(y_true)) == 2:
        metrics["roc_auc"] = float(roc_auc_score(y_true, probabilities))
        metrics["average_precision"] = float(average_precision_score(y_true, probabilities))

    save_json(metrics, output_dir / "live_benchmark_metrics.json")
    save_confusion_matrix_plot(
        matrix,
        "Live URL Benchmark - Calibrated Random Forest",
        output_dir / "live_benchmark_confusion_matrix.png",
    )
    return metrics
