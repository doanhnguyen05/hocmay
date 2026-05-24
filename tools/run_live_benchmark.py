from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cybershield_ai.live_benchmark import DEFAULT_MODEL_PATH, DEFAULT_OUTPUT_DIR, run_live_benchmark


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run an end-to-end live URL benchmark.")
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--phishing-count", type=int, default=250)
    parser.add_argument("--legitimate-count", type=int, default=250)
    parser.add_argument("--max-urls", type=int, default=None, help="Optional cap for smoke runs.")
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--delay-seconds", type=float, default=0.0)
    parser.add_argument("--progress-every", type=int, default=10)
    parser.add_argument("--quiet", action="store_true", help="Disable progress logs.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    metrics = run_live_benchmark(
        model_path=args.model_path,
        output_dir=args.output_dir,
        phishing_count=args.phishing_count,
        legitimate_count=args.legitimate_count,
        max_urls=args.max_urls,
        random_state=args.random_state,
        delay_seconds=args.delay_seconds,
        progress_every=args.progress_every,
        verbose=not args.quiet,
    )
    print(f"Live benchmark samples: {metrics['sample_count']}")
    print(f"Metrics: {args.output_dir / 'live_benchmark_metrics.json'}")
    print(f"Predictions: {metrics['predictions_path']}")


if __name__ == "__main__":
    main()
