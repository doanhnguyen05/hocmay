from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
import shap


def build_tree_explainer(model: Any, background: pd.DataFrame | None = None) -> shap.TreeExplainer:
    if background is not None and not background.empty:
        return shap.TreeExplainer(model, data=background, feature_perturbation="interventional")
    return shap.TreeExplainer(model)


def get_positive_class_explanation(
    explainer: shap.TreeExplainer,
    X: pd.DataFrame,
) -> shap.Explanation:
    raw_values = explainer.shap_values(X)
    expected_value = explainer.expected_value

    if isinstance(raw_values, list):
        shap_matrix = raw_values[1] if len(raw_values) > 1 else raw_values[0]
        base_value = expected_value[1] if np.ndim(expected_value) else expected_value
    elif isinstance(raw_values, np.ndarray) and raw_values.ndim == 3:
        shap_matrix = raw_values[:, :, 1]
        base_value = np.asarray(expected_value)[1] if np.ndim(expected_value) else expected_value
    else:
        shap_matrix = raw_values
        base_value = expected_value

    base_values = np.repeat(float(np.asarray(base_value).reshape(-1)[0]), len(X))
    return shap.Explanation(
        values=np.asarray(shap_matrix, dtype=float),
        base_values=base_values,
        data=X.to_numpy(),
        feature_names=list(X.columns),
    )
