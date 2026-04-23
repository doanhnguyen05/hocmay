from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from .config import FEATURE_COLUMNS

matplotlib.use("Agg")


def build_candidate_models(random_state: int = 42) -> dict[str, Any]:
    return {
        "Logistic Regression": Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "model",
                    LogisticRegression(
                        max_iter=2000,
                        class_weight="balanced",
                        solver="lbfgs",
                        random_state=random_state,
                    ),
                ),
            ]
        ),
        "SVM": Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "model",
                    SVC(
                        kernel="rbf",
                        probability=True,
                        class_weight="balanced",
                        random_state=random_state,
                    ),
                ),
            ]
        ),
        "Random Forest": RandomForestClassifier(random_state=random_state, n_jobs=-1),
    }


def build_cv(random_state: int = 42) -> StratifiedKFold:
    return StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)


def cross_validate_models(
    models: dict[str, Any],
    X_train: pd.DataFrame,
    y_train: pd.Series,
    cv: StratifiedKFold,
) -> pd.DataFrame:
    rows: list[dict[str, float | str]] = []
    scoring = {
        "accuracy": "accuracy",
        "precision": "precision",
        "recall": "recall",
        "f1": "f1",
        "roc_auc": "roc_auc",
    }
    for name, model in models.items():
        scores = cross_validate(
            clone(model),
            X_train,
            y_train,
            cv=cv,
            scoring=scoring,
            n_jobs=-1,
            return_train_score=False,
        )
        row: dict[str, float | str] = {"model": name}
        for metric_name in scoring:
            row[f"{metric_name}_mean"] = float(np.mean(scores[f"test_{metric_name}"]))
            row[f"{metric_name}_std"] = float(np.std(scores[f"test_{metric_name}"]))
        rows.append(row)
    return pd.DataFrame(rows).sort_values("f1_mean", ascending=False).reset_index(drop=True)


def tune_random_forest(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    cv: StratifiedKFold,
    quick: bool = False,
    random_state: int = 42,
) -> GridSearchCV:
    estimator = RandomForestClassifier(random_state=random_state, n_jobs=-1)
    param_grid = {
        "n_estimators": [200, 400],
        "max_depth": [None, 10, 20, 30],
        "min_samples_split": [2, 5, 10],
        "min_samples_leaf": [1, 2, 4],
        "max_features": ["sqrt", "log2"],
        "class_weight": [None, "balanced"],
    }
    if quick:
        param_grid = {
            "n_estimators": [100],
            "max_depth": [None, 12],
            "min_samples_split": [2, 5],
            "min_samples_leaf": [1, 2],
            "max_features": ["sqrt"],
            "class_weight": [None, "balanced"],
        }

    grid = GridSearchCV(
        estimator=estimator,
        param_grid=param_grid,
        scoring="f1",
        cv=cv,
        n_jobs=-1,
        refit=True,
        verbose=1,
    )
    grid.fit(X_train, y_train)
    return grid


def evaluate_model(
    model: Any,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> dict[str, Any]:
    probabilities = model.predict_proba(X_test)[:, 1]
    predictions = model.predict(X_test)
    fpr, tpr, thresholds = roc_curve(y_test, probabilities)
    report = classification_report(y_test, predictions, target_names=["legitimate", "phishing"], output_dict=True)
    report_text = classification_report(y_test, predictions, target_names=["legitimate", "phishing"])
    matrix = confusion_matrix(y_test, predictions)
    return {
        "predictions": predictions,
        "probabilities": probabilities,
        "confusion_matrix": matrix,
        "classification_report": report,
        "classification_report_text": report_text,
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "roc_curve": {
            "fpr": fpr.tolist(),
            "tpr": tpr.tolist(),
            "thresholds": thresholds.tolist(),
        },
    }


def save_confusion_matrix_plot(matrix: np.ndarray, title: str, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(
        matrix,
        annot=True,
        fmt="d",
        cmap="Blues",
        cbar=False,
        xticklabels=["Pred Legitimate", "Pred Phishing"],
        yticklabels=["Actual Legitimate", "Actual Phishing"],
        ax=ax,
    )
    ax.set_title(title)
    ax.set_xlabel("Du doan")
    ax.set_ylabel("Thuc te")
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def save_roc_curve_plot(results: dict[str, dict[str, Any]], path: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 5))
    for name, result in results.items():
        curve = result["roc_curve"]
        ax.plot(curve["fpr"], curve["tpr"], label=f"{name} (AUC={result['roc_auc']:.3f})")
    ax.plot([0, 1], [0, 1], linestyle="--", color="gray")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC-AUC so sanh mo hinh")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def save_feature_importance_plot(model: RandomForestClassifier, path: Path, top_n: int = 15) -> pd.DataFrame:
    importance_df = (
        pd.DataFrame(
            {
                "feature": FEATURE_COLUMNS,
                "importance": model.feature_importances_,
            }
        )
        .sort_values("importance", ascending=False)
        .reset_index(drop=True)
    )
    top_df = importance_df.head(top_n).iloc[::-1]

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(top_df["feature"], top_df["importance"], color="#0B6E4F")
    ax.set_title("Top dac trung quan trong cua Random Forest")
    ax.set_xlabel("Feature importance")
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)
    return importance_df


def save_json(data: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def precision_f1_explanation() -> str:
    return (
        "Trong bai toan chan website lua dao, Precision cao giup giam False Positive, "
        "tuc giam viec chan nham cac website hop le va tranh lam nguoi dung mat niem tin vao he thong. "
        "Tuy nhien, neu chi toi uu Precision ma Recall thap thi ta se bo sot nhieu trang phishing. "
        "F1-Score can bang giua Precision va Recall, vi vay phu hop hon Accuracy trong ngu canh an ninh mang, "
        "noi ma ca chan nham web tot (False Positive) lan bo lot web doc (False Negative) deu co chi phi rat lon."
    )
