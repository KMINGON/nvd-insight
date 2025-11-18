from __future__ import annotations

from pathlib import Path
from typing import Optional

import pandas as pd

from ..config import REPORTS_FIGURES_DIR
from .charts import build_yearly_cve_chart, save_figure


def plot_cve_trend(
    df: pd.DataFrame,
    output_dir: Optional[Path] = None,
    date_column: str = "published",
) -> Path:
    """
    Render a yearly CVE count chart and persist it under reports/figures by default.

    For interactive dashboards prefer importing
    ``src.analytics.charts.build_yearly_cve_chart`` directly so the raw figure can be
    returned to Streamlit without touching the filesystem.
    """
    output_dir = Path(output_dir or REPORTS_FIGURES_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "cve_trend.png"
    figure = build_yearly_cve_chart(df, date_column=date_column)
    return save_figure(figure, output_path)
