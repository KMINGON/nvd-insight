"""
Reusable chart builders for Streamlit and notebook consumers.

Each module should provide pure functions that accept a pandas.DataFrame and
return a Plotly/Altair figure without performing any 파일 I/O. This keeps the
chart definitions composable so the Streamlit UI can mix and match visualizations.
"""

from .analysis_example import (
    build_yearly_cve_chart,
    save_figure,
    summarize_counts_by_year,
)
from .cvss import (
    build_cwe_top_chart,
    build_cvss_score_bin_chart,
    build_cvss_severity_chart,
    build_dayofweek_chart,
    build_hourly_chart,
    build_monthly_count_chart,
    extract_cvss_metrics,
    summarize_cvss_availability,
)

__all__ = [
    "build_yearly_cve_chart",
    "save_figure",
    "summarize_counts_by_year",
    "build_monthly_count_chart",
    "build_dayofweek_chart",
    "build_hourly_chart",
    "build_cvss_severity_chart",
    "build_cvss_score_bin_chart",
    "build_cwe_top_chart",
    "summarize_cvss_availability",
    "extract_cvss_metrics",
]
