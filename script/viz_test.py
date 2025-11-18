"""
Lightweight visualization test runner that writes outputs to a separate folder.

Usage:
    python script/viz_test.py
    python script/viz_test.py --limit 5000 --output-dir reports/figures/test_run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analytics.viz import load_processed_dataframe, plot_cve_trend, plot_cvss_distributions  # noqa: E402

DEFAULT_OUTPUT = PROJECT_ROOT / "reports" / "figures" / "test"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate CVE/CVSS visualizations into a test folder."
    )
    parser.add_argument(
        "--dataset",
        type=str,
        help="Path to processed dataset (file or dir). Defaults to data/processed/cve_cwe_by_year.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(DEFAULT_OUTPUT),
        help="Where to write test figures (default: reports/figures/test).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Optional row limit for quick checks (e.g., 5000).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)

    df = load_processed_dataframe(Path(args.dataset) if args.dataset else None)
    if args.limit:
        df = df.head(args.limit)
        print(f"[info] limiting dataframe to first {args.limit} rows for a quick test")
    print(f"[info] records loaded: {len(df)}")

    trend_path = plot_cve_trend(df, output_dir=output_dir)
    print(f"[ok] trend figure -> {trend_path} (png if kaleido available, else html)")

    v31 = plot_cvss_distributions(df, output_dir=output_dir, version="v31")
    print(f"[ok] CVSS v3.1 figures -> {v31}")

    v2 = plot_cvss_distributions(df, output_dir=output_dir, version="v2")
    print(f"[ok] CVSS v2 figures -> {v2}")


if __name__ == "__main__":
    main()
