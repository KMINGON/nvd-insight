from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import pandas as pd
import plotly.express as px

from ..config import PROCESSED_DATASET_DIR, REPORTS_FIGURES_DIR


def load_processed_dataframe(dataset_path: Optional[Path] = None) -> pd.DataFrame:
    """
    Load the processed dataset into a pandas DataFrame.

    TODO: replace eager loading with chunked ingestion if dataset size becomes a bottleneck.
    """
    dataset_path = Path(dataset_path or PROCESSED_DATASET_DIR)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Processed dataset not found: {dataset_path}")
    records: List[dict] = []
    if dataset_path.is_dir():
        files = sorted(dataset_path.glob("cve_cwe_dataset_*.json"))
        if not files:
            raise FileNotFoundError(f"No yearly dataset JSON files found under {dataset_path}")
        for file in files:
            with file.open("r", encoding="utf-8") as fh:
                records.extend(json.load(fh))
    else:
        with dataset_path.open("r", encoding="utf-8") as fh:
            records = json.load(fh)
    df = pd.json_normalize(records)
    # TODO: push nested column flattening (cpes/cwes) into dedicated transformers once analytics requirements are firm.
    return df


def plot_cve_trend(
    df: pd.DataFrame,
    output_dir: Optional[Path] = None,
    date_column: str = "published",
) -> Path:
    """
    Render a yearly CVE count chart and persist it under reports/figures by default.

    TODO: extend with severity filters and interactive widgets for Streamlit dashboards.
    """
    if date_column not in df:
        raise ValueError(f"{date_column} column missing from dataframe")
    series = (
        pd.to_datetime(df[date_column], errors="coerce")
        .dt.year.value_counts()
        .sort_index()
    )
    fig = px.bar(x=series.index, y=series.values, labels={"x": "Year", "y": "CVE Count"})
    output_dir = Path(output_dir or REPORTS_FIGURES_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "cve_trend.png"
    fig.write_image(str(output_path))
    return output_path
