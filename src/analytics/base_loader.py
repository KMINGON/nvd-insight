from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Union

import pandas as pd

from ..config import PROCESSED_DATASET_DIR, PROCESSED_DATASET_PATTERN

PathLike = Union[str, Path]


def iter_dataset_files(
    dataset_path: Optional[PathLike] = None,
    *,
    years: Optional[Sequence[int]] = None,
    dataset_dir: Optional[PathLike] = None,
) -> Iterator[Path]:
    """
    Yield processed dataset files that match the provided filters.

    Args:
        dataset_path: Optional path pointing to either a single JSON file or a directory
            that contains yearly processed datasets.
        years: Explicit list of years to load. When omitted, all datasets under
            the resolved directory are returned.
        dataset_dir: Alternative root directory for processed datasets.
    """
    root_candidate: Path = Path(dataset_path or dataset_dir or PROCESSED_DATASET_DIR)
    if not root_candidate.exists():
        raise FileNotFoundError(f"Processed dataset path not found: {root_candidate}")

    if root_candidate.is_file():
        if years:
            raise ValueError("Cannot filter by year when dataset_path points to a single file.")
        yield root_candidate
        return

    directory = root_candidate
    if years:
        for year in years:
            year_file = directory / PROCESSED_DATASET_PATTERN.format(year=year)
            if not year_file.exists():
                raise FileNotFoundError(f"Dataset for year {year} not found under {directory}")
            yield year_file
        return

    files = sorted(directory.glob("cve_cwe_dataset_*.json"))
    if not files:
        raise FileNotFoundError(f"No processed dataset JSON files found under {directory}")
    for file in files:
        yield file


def load_processed_records(
    dataset_path: Optional[PathLike] = None,
    *,
    years: Optional[Sequence[int]] = None,
    dataset_dir: Optional[PathLike] = None,
) -> List[dict]:
    """
    Load processed records as a Python list for lightweight consumers.
    """
    records: List[dict] = []
    for file in iter_dataset_files(dataset_path, years=years, dataset_dir=dataset_dir):
        with file.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
            if isinstance(payload, list):
                records.extend(payload)
            else:
                raise ValueError(f"Dataset {file} must contain a JSON array.")
    return records


def load_processed_dataframe(
    dataset_path: Optional[PathLike] = None,
    *,
    years: Optional[Sequence[int]] = None,
    dataset_dir: Optional[PathLike] = None,
) -> pd.DataFrame:
    """
    Load processed datasets into a pandas DataFrame.

    This function normalizes nested columns with dot notation, so downstream
    chart builders can reliably access fields like ``metrics.cvssMetricV31``.
    """
    records = load_processed_records(dataset_path, years=years, dataset_dir=dataset_dir)
    if not records:
        raise ValueError("No processed records were loaded; confirm the dataset path/year filters.")
    return pd.json_normalize(records)


__all__ = [
    "iter_dataset_files",
    "load_processed_records",
    "load_processed_dataframe",
]
