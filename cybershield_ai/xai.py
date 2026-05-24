"""Giải thích mô hình bằng SHAP (SHapley Additive exPlanations).

Module này cung cấp các hàm tiện ích để tạo ``TreeExplainer`` cho mô hình
cây quyết định và trích xuất giá trị SHAP cho lớp dương (phishing),
phục vụ hiển thị biểu đồ waterfall và tóm tắt nguyên nhân rủi ro.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
import shap

def build_tree_explainer(model: Any, background: pd.DataFrame | None = None) -> shap.TreeExplainer:
    """Tạo đối tượng ``shap.TreeExplainer`` cho mô hình cây.

    Nếu cung cấp *background* (mẫu nền từ tập huấn luyện), sử dụng
    chế độ ``interventional`` để giải thích chính xác hơn khi các
    đặc trưng có tương quan. Nếu không, dùng chế độ mặc định.

    Args:
        model: Mô hình cây đã huấn luyện (ví dụ ``XGBClassifier``,
            ``RandomForestClassifier``).
        background: DataFrame mẫu nền (một phần nhỏ tập huấn luyện).
            Nếu ``None`` hoặc rỗng, không dùng dữ liệu nền.

    Returns:
        Đối tượng ``shap.TreeExplainer`` sẵn sàng tính SHAP values.
    """
    if background is not None and not background.empty:
        return shap.TreeExplainer(model, data=background, feature_perturbation="interventional")
    return shap.TreeExplainer(model)


def get_positive_class_explanation(
    explainer: shap.TreeExplainer,
    X: pd.DataFrame,
) -> shap.Explanation:
    """Tính giá trị SHAP cho lớp dương (phishing) và đóng gói thành ``Explanation``.

    Hàm xử lý nhiều định dạng đầu ra khác nhau của ``shap_values``
    (list của 2 mảng, mảng 3D, hoặc mảng 2D) để luôn trả về giá trị
    SHAP tương ứng với lớp 1 (phishing).

    Args:
        explainer: Đối tượng ``TreeExplainer`` đã khởi tạo.
        X: DataFrame chứa các mẫu cần giải thích (có thể 1 hoặc
            nhiều dòng).

    Returns:
        ``shap.Explanation`` chứa giá trị SHAP, base values, dữ liệu
        và tên đặc trưng — sẵn sàng để vẽ biểu đồ waterfall.
    """
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
