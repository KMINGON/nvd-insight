"""
Analytics helpers built on top of pandas-based pipelines.

The functions exported here intentionally keep only lightweight dependencies
so notebooks and Streamlit UI can import them without circular references.
"""

from .base_loader import iter_dataset_files, load_processed_dataframe, load_processed_records
from .charts import build_yearly_cve_chart, summarize_counts_by_year
from .rag_report import summarize_with_rag
from .viz import plot_cve_trend

__all__ = [
    "build_yearly_cve_chart",
    "iter_dataset_files",
    "load_processed_dataframe",
    "load_processed_records",
    "plot_cve_trend",
    "summarize_with_rag",
    "summarize_counts_by_year",
]
