"""
Reusable chart builders for Streamlit and notebook consumers.

Each module should provide pure functions that accept a pandas.DataFrame and
return a Plotly/Altair figure without performing any 파일 I/O. This keeps the
chart definitions composable so the Streamlit UI can mix and match visualizations.
"""

from .analysis_example import (
    build_yearly_cve_chart,
    summarize_counts_by_year,
)
from .cvss import build_dayofweek_chart, build_hourly_chart, build_monthly_count_chart
from .cvss_app import (
    build_cvss_score_bin_chart,
    build_cvss_severity_chart,
    extract_cvss_metrics,
    summarize_cvss_availability,
)
from .cwe import build_cwe_top_chart, summarize_cwe_counts
from .high_risk import (
    build_high_risk_cwe_chart,
    build_high_risk_product_chart,
    build_high_risk_vendor_chart,
    summarize_high_risk_by_cwe,
    summarize_high_risk_by_product,
    summarize_high_risk_by_vendor,
)
from .skr_score import (
    build_cwe_score_chart,
    build_product_score_chart,
    build_skr_score_added_df,
    build_top10_chart,
    build_vendor_score_chart,
    extract_cvss_payload,
    load_records_for_year,
    normalize_years,
    build_top10_dataset,
    summarize_cwe_scores,
    summarize_product_counts,
    summarize_vendor_counts,
)

__all__ = [
    "build_yearly_cve_chart",
    "summarize_counts_by_year",
    "build_monthly_count_chart",
    "build_dayofweek_chart",
    "build_hourly_chart",
    "build_cvss_severity_chart",
    "build_cvss_score_bin_chart",
    "summarize_cwe_counts",
    "build_cwe_top_chart",
    "summarize_cvss_availability",
    "extract_cvss_metrics",
    "summarize_high_risk_by_vendor",
    "summarize_high_risk_by_product",
    "summarize_high_risk_by_cwe",
    "build_high_risk_vendor_chart",
    "build_high_risk_product_chart",
    "build_high_risk_cwe_chart",
    "build_skr_score_added_df",
    "build_top10_chart",
    "build_top10_dataset",
    "normalize_years",
    "load_records_for_year",
    "extract_cvss_payload",
    "summarize_vendor_counts",
    "summarize_product_counts",
    "summarize_cwe_scores",
    "build_vendor_score_chart",
    "build_product_score_chart",
    "build_cwe_score_chart",
]
