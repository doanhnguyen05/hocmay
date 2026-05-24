"""CLI huấn luyện CyberShield AI.

Script dòng lệnh cho phép chạy toàn bộ pipeline huấn luyện:
tải dữ liệu UCI, tune công bằng Logistic Regression/SVM/Random Forest,
chạy feature selection, xuất báo cáo và lưu model artifact.

Sử dụng::

    python train.py              # Chạy đầy đủ
    python train.py --quick      # Smoke-test nhanh
    python train.py --sample-size 2000  # Giới hạn mẫu
"""

from __future__ import annotations

import argparse

from cybershield_ai.training_pipeline import run_training_pipeline


def build_parser() -> argparse.ArgumentParser:
    """Tạo argument parser cho CLI huấn luyện.

    Returns:
        ``ArgumentParser`` với các tuỳ chọn ``--quick`` và ``--sample-size``.
    """
    parser = argparse.ArgumentParser(description="Huấn luyện CyberShield AI với UCI Phishing Websites Dataset.")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Chay ban quick smoke-test voi grid nho hon de kiem thu nhanh.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=None,
        help="Lay mau ngau nhien co can bang nhan truoc khi train.",
    )
    parser.add_argument(
        "--calibration-size",
        type=float,
        default=0.15,
        help="Ty le train split dung de calibrate xac suat va tune threshold.",
    )
    parser.add_argument(
        "--calibration-method",
        choices=["sigmoid", "isotonic"],
        default="sigmoid",
        help="Phuong phap calibration xac suat.",
    )
    parser.add_argument(
        "--threshold-metric",
        choices=["f1", "precision", "recall"],
        default="f1",
        help="Metric dung de chon nguong canh bao phishing.",
    )
    parser.add_argument(
        "--threshold-min-recall",
        type=float,
        default=None,
        help="Neu dat, chi chon threshold co recall toi thieu tren calibration split.",
    )
    parser.add_argument(
        "--feature-selection-k-values",
        type=str,
        default="10,15,20,30",
        help="Danh sach top-k Mutual Information can so sanh, vi du: 10,15,20,30.",
    )
    parser.add_argument(
        "--no-learning-curves",
        action="store_true",
        help="Bo qua learning curve de chay nhanh hon.",
    )
    return parser


def main() -> None:
    """Chạy pipeline huấn luyện và in kết quả ra console."""
    args = build_parser().parse_args()
    k_values = tuple(int(item.strip()) for item in args.feature_selection_k_values.split(",") if item.strip())
    results = run_training_pipeline(
        quick=args.quick,
        sample_size=args.sample_size,
        calibration_size=args.calibration_size,
        calibration_method=args.calibration_method,
        threshold_metric=args.threshold_metric,
        threshold_min_recall=args.threshold_min_recall,
        feature_selection_k_values=k_values,
        generate_learning_curves=not args.no_learning_curves,
    )
    print("Da hoan tat huan luyen CyberShield AI.")
    print(f"Model artifact: {results['artifact_path']}")
    print(f"Bao cao: {results['reports_dir']}")
    print(f"Selected features: top {results['selected_feature_count']} by Mutual Information")
    print(f"Decision threshold: {results['decision_threshold']:.4f}")
    print("Tuned model summary:")
    print(results["tuning_summary"].to_string(index=False))
    print("Top CV results:")
    print(results["cv_results"].to_string(index=False))


if __name__ == "__main__":
    main()
