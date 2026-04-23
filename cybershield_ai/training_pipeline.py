from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
import shap
from sklearn.model_selection import train_test_split

from .config import FEATURE_COLUMNS, MODEL_DIR, REPORT_DIR
from .data_loader import compute_feature_defaults, ensure_project_dirs, load_uci_dataset
from .feature_extraction import configure_feature_defaults
from .modeling import (
    build_candidate_models,
    build_cv,
    cross_validate_models,
    evaluate_model,
    precision_f1_explanation,
    save_confusion_matrix_plot,
    save_feature_importance_plot,
    save_json,
    save_roc_curve_plot,
    tune_random_forest,
)
from .xai import build_tree_explainer, get_positive_class_explanation

matplotlib.use("Agg")


def run_training_pipeline(
    quick: bool = False,
    sample_size: int | None = None,
    random_state: int = 42,
    output_model_path: Path | None = None,
) -> dict[str, Any]:
    ensure_project_dirs()
    if output_model_path is not None:
        output_model_path.parent.mkdir(parents=True, exist_ok=True)
    dataset = load_uci_dataset(force_download=False)
    X = dataset.X.copy()
    y = dataset.y.copy()

    if sample_size is not None and sample_size < len(X):
        per_class = max(1, sample_size // 2)
        combined = pd.concat([X, y], axis=1)
        sampled_parts = [
            frame.sample(min(len(frame), per_class), random_state=random_state)
            for _, frame in combined.groupby("is_phishing")
        ]
        sampled = pd.concat(sampled_parts).sample(frac=1.0, random_state=random_state).reset_index(drop=True)
        X = sampled[FEATURE_COLUMNS]
        y = sampled["is_phishing"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        stratify=y,
        random_state=random_state,
    )

    feature_defaults = compute_feature_defaults(X_train)
    configure_feature_defaults(feature_defaults)

    candidate_models = build_candidate_models(random_state=random_state)
    cv = build_cv(random_state=random_state)
    cv_results = cross_validate_models(candidate_models, X_train, y_train, cv)

    tuned_rf = tune_random_forest(X_train, y_train, cv=cv, quick=quick, random_state=random_state)
    best_rf = tuned_rf.best_estimator_

    fitted_models: dict[str, Any] = {}
    for name, model in candidate_models.items():
        if name == "Random Forest":
            fitted_models[name] = best_rf
        else:
            fitted_models[name] = model.fit(X_train, y_train)

    evaluation_results = {
        name: evaluate_model(model, X_test, y_test) for name, model in fitted_models.items()
    }

    for name, result in evaluation_results.items():
        slug = name.lower().replace(" ", "_")
        save_confusion_matrix_plot(
            result["confusion_matrix"],
            title=f"Confusion Matrix - {name}",
            path=REPORT_DIR / f"confusion_matrix_{slug}.png",
        )

    save_roc_curve_plot(evaluation_results, REPORT_DIR / "roc_auc_comparison.png")
    importance_df = save_feature_importance_plot(best_rf, REPORT_DIR / "random_forest_feature_importance.png")
    importance_df.to_csv(REPORT_DIR / "random_forest_feature_importance.csv", index=False)

    background = X_train.sample(min(200, len(X_train)), random_state=random_state).reset_index(drop=True)
    shap_sample = X_test.sample(min(250, len(X_test)), random_state=random_state).reset_index(drop=True)
    explainer = build_tree_explainer(best_rf, background)
    shap_explanation = get_positive_class_explanation(explainer, shap_sample)
    shap.summary_plot(shap_explanation, shap_sample, show=False)
    plt.tight_layout()
    plt.savefig(REPORT_DIR / "shap_summary.png", dpi=180, bbox_inches="tight")
    plt.close()

    artifact = {
        "model": best_rf,
        "feature_columns": FEATURE_COLUMNS,
        "feature_defaults": feature_defaults,
        "label_mapping": {"legitimate": 0, "phishing": 1},
        "background_data": background,
        "best_params": tuned_rf.best_params_,
        "precision_f1_explanation": precision_f1_explanation(),
    }
    model_path = output_model_path or (MODEL_DIR / "cybershield_ai_model.joblib")
    joblib.dump(artifact, model_path)

    metrics_payload = {
        "cv_results": cv_results.to_dict(orient="records"),
        "best_random_forest_params": tuned_rf.best_params_,
        "evaluation_results": {
            name: {
                "roc_auc": result["roc_auc"],
                "classification_report": result["classification_report"],
            }
            for name, result in evaluation_results.items()
        },
        "precision_f1_explanation": precision_f1_explanation(),
    }
    cv_results.to_csv(REPORT_DIR / "cv_results.csv", index=False)
    save_json(metrics_payload, REPORT_DIR / "metrics_summary.json")

    for name, result in evaluation_results.items():
        slug = name.lower().replace(" ", "_")
        (REPORT_DIR / f"classification_report_{slug}.txt").write_text(
            result["classification_report_text"],
            encoding="utf-8",
        )

    return {
        "artifact_path": str(model_path),
        "cv_results": cv_results,
        "best_params": tuned_rf.best_params_,
        "evaluation_results": evaluation_results,
        "reports_dir": str(REPORT_DIR),
    }
