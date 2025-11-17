"""
Analytics helpers built on top of pandas-based pipelines.

The functions exported here intentionally keep only lightweight dependencies
so notebooks and Streamlit UI can import them without circular references.
"""

from .viz import load_processed_dataframe, plot_cve_trend
from .rag_report import summarize_with_rag

__all__ = ["load_processed_dataframe", "plot_cve_trend", "summarize_with_rag"]
