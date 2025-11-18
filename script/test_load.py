from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analytics.base_loader import load_processed_dataframe
from src.config import PROCESSED_DATASET_DIR, PROCESSED_DATASET_PATTERN


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="charts 모듈 개발 시 사용할 정규화 데이터 로딩 확인용 스크립트"
    )
    parser.add_argument(
        "--dataset-path",
        type=str,
        help="연도별 JSON이 들어있는 디렉터리 또는 단일 JSON 파일 경로",
    )
    parser.add_argument(
        "--years",
        type=int,
        nargs="+",
        help="로딩할 연도 목록 (예: --years 2023 2024)",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=3,
        help="기본 출력에 표시할 레코드 수",
    )
    return parser.parse_args()


def describe_dataframe(df, sample_size: int) -> None:
    print("=" * 60)
    print("데이터셋 개요")
    print(f"- 총 레코드 수: {len(df):,}")
    print(f"- 컬럼 수: {len(df.columns)}")
    preview_columns = list(df.columns[:10])
    remainder = len(df.columns) - len(preview_columns)
    print(f"- 주요 컬럼(최대 10개): {preview_columns}", end="")
    if remainder > 0:
        print(f" ... (+{remainder} more)")
    else:
        print()
    print("- dtypes 요약:")
    print(df.dtypes.head(10))
    print("=" * 60)

    print(f"상위 {sample_size}개 레코드 샘플:")
    print(df.head(sample_size)[["cveId", "published", "description"]])
    if "cpes" in df.columns:
        print("\n각 레코드의 CPE 항목 개수 (앞 {0}개):".format(sample_size))
        print(df["cpes"].head(sample_size).apply(lambda items: len(items) if isinstance(items, list) else 0))
    if "cwes" in df.columns:
        print("\n각 레코드의 CWE 항목 개수 (앞 {0}개):".format(sample_size))
        print(df["cwes"].head(sample_size).apply(lambda items: len(items) if isinstance(items, list) else 0))


def verify_year_files(years: Optional[Iterable[int]]) -> None:
    if not years:
        return
    missing: List[int] = []
    for year in years:
        path = PROCESSED_DATASET_DIR / PROCESSED_DATASET_PATTERN.format(year=year)
        if not path.exists():
            missing.append(year)
    if missing:
        raise FileNotFoundError(
            f"다음 연도의 정규화 파일을 찾을 수 없습니다: {missing}. "
            f"빌드 여부를 확인하거나 --dataset-path 옵션을 사용하세요."
        )

def main() -> None:
    args = parse_args()
    verify_year_files(args.years)
    df = load_processed_dataframe(dataset_path=args.dataset_path, years=args.years)
    describe_dataframe(df, args.sample)


if __name__ == "__main__":
    main()
