from __future__ import annotations

import joblib
import matplotlib.pyplot as plt
import pandas as pd
import shap
import streamlit as st

from cybershield_ai.config import FEATURE_FRIENDLY_NAMES, MODEL_DIR
from cybershield_ai.feature_extraction import configure_feature_defaults, scan_url
from cybershield_ai.xai import build_tree_explainer, get_positive_class_explanation

MODEL_PATH = MODEL_DIR / "cybershield_ai_model.joblib"


@st.cache_resource(show_spinner=False)
def load_artifact(model_path: str) -> dict:
    artifact = joblib.load(model_path)
    configure_feature_defaults(artifact["feature_defaults"])
    return artifact


@st.cache_resource(show_spinner=False)
def build_explainer(model_path: str):
    artifact = load_artifact(model_path)
    background = artifact.get("background_data")
    return build_tree_explainer(artifact["model"], background)


def render_shap_waterfall(explanation: shap.Explanation) -> None:
    plt.figure(figsize=(10, 5))
    shap.plots.waterfall(explanation[0], max_display=10, show=False)
    st.pyplot(plt.gcf(), clear_figure=True)


def summarize_shap(explanation: shap.Explanation, feature_row: pd.DataFrame) -> str:
    values = pd.Series(explanation.values[0], index=feature_row.columns)
    positive = values.sort_values(ascending=False)
    top_positive = [feature for feature, value in positive.items() if value > 0][:3]
    if not top_positive:
        return "Rủi ro hiện tại chưa có đặc trưng nào nổi trội theo SHAP."
    phrases = [FEATURE_FRIENDLY_NAMES.get(feature, feature) for feature in top_positive]
    return "Rủi ro tăng do " + ", ".join(phrases) + "."


def main() -> None:
    st.set_page_config(page_title="CyberShield AI", page_icon="🔒", layout="wide")
    st.markdown(
        """
        <style>
        .stTextInput input {
            font-size: 1.2rem;
            padding: 0.85rem 1rem;
        }
        .block-container {
            max-width: 1100px;
            padding-top: 2rem;
            padding-bottom: 2rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.title("CyberShield AI")

    if not MODEL_PATH.exists():
        st.error("Chưa tìm thấy model artifact. Hãy chạy `python train.py` trước.")
        st.stop()

    artifact = load_artifact(str(MODEL_PATH))
    explainer = build_explainer(str(MODEL_PATH))

    url_input = st.text_input(
        "🔒 Nhập đường link (URL) cần kiểm tra vào đây...",
        placeholder="https://example.com/login",
    )
    run_scan = st.button("Quét Radar", type="primary", use_container_width=True)

    if not run_scan:
        return

    if not url_input.strip():
        st.warning("Hãy nhập một URL để quét.")
        return

    with st.spinner("Đang quét URL, bóc tách đặc trưng và giải thích bằng SHAP..."):
        scan_result = scan_url(url_input, feature_defaults=artifact["feature_defaults"])
        feature_row = pd.DataFrame([scan_result["features"]], columns=artifact["feature_columns"])
        prediction = int(artifact["model"].predict(feature_row)[0])
        probability = float(artifact["model"].predict_proba(feature_row)[0, 1])
        explanation = get_positive_class_explanation(explainer, feature_row)

    col_left, col_right = st.columns([1.2, 1])
    with col_left:
        if prediction == 1:
            st.error("🚨 NGUY HIỂM: Phát hiện dấu hiệu Phishing!")
        else:
            st.success("✅ Web An toàn")

        st.metric("Điểm rủi ro (xác suất phishing)", f"{probability:.2%}")
        st.info(f"Loại rủi ro nghi ngờ: **{scan_result['risk_category_label']}**")
        st.caption(scan_result["risk_summary"])
        if scan_result["risk_signals"]:
            for signal in scan_result["risk_signals"]:
                st.caption(f"- {signal}")
        st.write(summarize_shap(explanation, feature_row))

        if scan_result["warnings"]:
            st.warning("Một số tín hiệu live không truy vấn được. Hệ thống đã dùng fallback để vẫn trả kết quả.")
            for warning in scan_result["warnings"][:6]:
                st.caption(f"- {warning}")

        with st.expander("Xem bộ đặc trưng đã bóc tách"):
            st.dataframe(feature_row.T.rename(columns={0: "value"}), use_container_width=True)

    with col_right:
        st.subheader("Giải thích SHAP cho URL này")
        render_shap_waterfall(explanation)

    with st.expander("Bằng chứng kỹ thuật từ quá trình quét"):
        if scan_result["evidence"]:
            for key, value in scan_result["evidence"].items():
                st.write(f"- **{key}**: {value}")
        else:
            st.write("Không có bằng chứng chi tiết nào được ghi nhận.")


if __name__ == "__main__":
    main()
