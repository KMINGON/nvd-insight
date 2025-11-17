import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src import config

try:
    import pandas as pd
except ImportError:  # pragma: no cover
    pd = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="연도별 정규화 CVE 데이터를 확인하는 도구")
    parser.add_argument(
        "--file",
        type=str,
        help="직접 지정한 JSON 파일 경로 (연도별 파일 패턴 무시)",
    )
    parser.add_argument(
        "--year",
        type=int,
        help="확인하고 싶은 연도 (예: 2021). 지정하지 않으면 가장 최신 연도 파일을 사용",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=5,
        help="상세 출력에 사용할 상위 CVE 수",
    )
    return parser.parse_args()


def resolve_dataset_path(file_path: str | None, year: int | None) -> Path:
    if file_path:
        return Path(file_path)
    dataset_dir = config.PROCESSED_DATASET_DIR
    if year is not None:
        target = dataset_dir / config.PROCESSED_DATASET_PATTERN.format(year=year)
        if not target.exists():
            raise FileNotFoundError(f"{target} 경로에 연도별 파일이 없습니다.")
        return target
    files = sorted(dataset_dir.glob("cve_cwe_dataset_*.json"))
    if not files:
        raise FileNotFoundError(f"{dataset_dir}에 연도별 JSON 파일이 없습니다.")
    return files[-1]


def load_and_preview_cve_data(file_path: Path, top_n: int = 5) -> None:
    """
    Load the CVE dataset from a JSON file and preview the data.
    Prints nested JSON structures (metrics/cpes/cwes) in detail so
    downstream developers can verify column-level values.
    """
    try:
        with file_path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if pd is not None:
            df = pd.DataFrame(data)
            print("Dataset Information:")
            print(df.info())
            print("\n")

            print("Preview of the dataset:")
            print(df.head(top_n))
            print("\n")

            if "cveId" in df.columns:
                print("Unique CVE IDs and their counts:")
                print(df["cveId"].value_counts().head(top_n))
                print("\n")
        else:
            print("pandas is not installed; skipping tabular preview and displaying raw counts only.")
            print(f"Total CVE entries: {len(data)}\n")

        print(f"Detailed inspection of the first {top_n} CVE entries (including nested fields):")
        for row in data[:top_n]:
            print("=" * 80)
            print(f"CVE ID: {row.get('cveId')}")
            for key, value in row.items():
                print(f"- {key}:")
                pretty_print_nested(value, indent=2)
            print("\n")

    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON - {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def pretty_print_nested(value: Any, indent: int = 0, max_list_items: int = 3) -> None:
    """
    Recursively print nested dictionaries/lists with indentation so every
    column (even deeply nested) is visible.
    """
    prefix = " " * indent
    if isinstance(value, dict):
        if not value:
            print(f"{prefix}(empty dict)")
        for key, val in value.items():
            print(f"{prefix}{key}:")
            pretty_print_nested(val, indent + 2, max_list_items)
    elif isinstance(value, list):
        if not value:
            print(f"{prefix}(empty list)")
            return
        print(f"{prefix}[list with {len(value)} items]")
        for idx, item in enumerate(value[:max_list_items]):
            print(f"{prefix}- item #{idx + 1}:")
            pretty_print_nested(item, indent + 4, max_list_items)
        if len(value) > max_list_items:
            remaining = len(value) - max_list_items
            print(f"{prefix}... ({remaining} more items)")
    else:
        print(f"{prefix}{value}")


if __name__ == "__main__":
    args = parse_args()
    dataset_path = resolve_dataset_path(args.file, args.year)
    load_and_preview_cve_data(dataset_path, top_n=args.top_n)
