from __future__ import annotations

from pathlib import Path

import joblib
import pytest

from cybershield_ai.config import FEATURE_COLUMNS
from cybershield_ai.feature_extraction import scan_url
from cybershield_ai.training_pipeline import run_training_pipeline


@pytest.mark.slow
def test_quick_training_pipeline_creates_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cybershield_ai.feature_extraction._hydrate_live_context", lambda context: None)
    artifact_path = tmp_path / "cybershield_test_model.joblib"
    results = run_training_pipeline(
        quick=True,
        sample_size=1200,
        output_model_path=artifact_path,
        output_report_dir=tmp_path / "reports",
        generate_learning_curves=False,
    )

    assert artifact_path.exists()
    assert Path(results["artifact_path"]).exists()

    artifact = joblib.load(artifact_path)
    assert set(artifact["feature_columns"]).issubset(set(FEATURE_COLUMNS))
    assert artifact["all_feature_columns"] == FEATURE_COLUMNS
    assert artifact["selected_feature_count"] == len(artifact["feature_columns"])
    assert "model" in artifact
    assert "feature_defaults" in artifact

    scan_result = scan_url("http://secure-login-bank.com@hack.it/", feature_defaults=artifact["feature_defaults"])
    feature_vector = [scan_result["features"][column] for column in FEATURE_COLUMNS]
    assert len(feature_vector) == 30
