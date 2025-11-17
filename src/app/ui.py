from __future__ import annotations

from typing import Optional

import streamlit as st

from ..analytics import load_processed_dataframe, plot_cve_trend
from ..config import PROCESSED_DATASET_DIR
from ..rag import RagRetriever
from .chat import streamlit_chat


def run_app(dataset_path: Optional[str] = None) -> None:
    """
    Streamlit entry point.

    TODO: add session state for selected CVE IDs and persist chat history.
    """
    st.set_page_config(page_title="CVE/CWE Mini Explorer", layout="wide")
    st.title("CVE / CWE 분석 대시보드")
    dataset_path = dataset_path or str(PROCESSED_DATASET_DIR)

    if st.sidebar.button("Reload dataset"):
        st.cache_data.clear()

    df = st.cache_data(load_processed_dataframe)(dataset_path)
    st.metric("총 CVE 건수", len(df))

    if st.button("연도별 추이 갱신"):
        figure_path = plot_cve_trend(df)
        st.success(f"시각화가 저장되었습니다: {figure_path}")

    with st.expander("검색/챗봇", expanded=True):
        retriever = RagRetriever()
        # TODO: handle index loading errors gracefully once FAISS build is ready.
        streamlit_chat(retriever)


if __name__ == "__main__":
    run_app()
