from __future__ import annotations

import argparse

from cybershield_ai.training_pipeline import run_training_pipeline


def build_parser() -> argparse.ArgumentParser:
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
    return parser


def main() -> None:
    args = build_parser().parse_args()
    results = run_training_pipeline(quick=args.quick, sample_size=args.sample_size)
    print("Da hoan tat huan luyen CyberShield AI.")
    print(f"Model artifact: {results['artifact_path']}")
    print(f"Bao cao: {results['reports_dir']}")
    print("Top CV results:")
    print(results["cv_results"].to_string(index=False))


if __name__ == "__main__":
    main()
