from __future__ import annotations

from pathlib import Path

import joblib

from cybershield_ai.config import FEATURE_COLUMNS
from cybershield_ai.feature_extraction import scan_url
from cybershield_ai.training_pipeline import run_training_pipeline


def test_quick_training_pipeline_creates_artifact(tmp_path: Path) -> None:
    artifact_path = tmp_path / "cybershield_test_model.joblib"
    results = run_training_pipeline(quick=True, sample_size=1200, output_model_path=artifact_path)

    assert artifact_path.exists()
    assert Path(results["artifact_path"]).exists()

    artifact = joblib.load(artifact_path)
    assert artifact["feature_columns"] == FEATURE_COLUMNS
    assert "model" in artifact
    assert "feature_defaults" in artifact

    scan_result = scan_url("http://secure-login-bank.com@hack.it/", feature_defaults=artifact["feature_defaults"])
    feature_vector = [scan_result["features"][column] for column in FEATURE_COLUMNS]
    assert len(feature_vector) == 30
