"""
Reusable chart builders for Streamlit and notebook consumers.

Each module should provide pure functions that accept a pandas.DataFrame and
return a Plotly/Altair figure without performing any 파일 I/O. This keeps the
chart definitions composable so the Streamlit UI can mix and match visualizations.
"""

from .analysis_example import build_yearly_cve_chart, save_figure, summarize_counts_by_year
from .high_risk import (
    build_high_risk_cwe_chart,
    build_high_risk_product_chart,
    build_high_risk_vendor_chart,
    summarize_high_risk_by_cwe,
    summarize_high_risk_by_product,
    summarize_high_risk_by_vendor,
)

__all__ = [
    "build_yearly_cve_chart",
    "save_figure",
    "summarize_counts_by_year",
    "summarize_high_risk_by_vendor",
    "summarize_high_risk_by_product",
    "summarize_high_risk_by_cwe",
    "build_high_risk_vendor_chart",
    "build_high_risk_product_chart",
    "build_high_risk_cwe_chart",
]
