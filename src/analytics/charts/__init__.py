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

__all__ = ["build_yearly_cve_chart", "save_figure", "summarize_counts_by_year"]
