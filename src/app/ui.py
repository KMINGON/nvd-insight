from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import streamlit as st

try:
    from ..analytics import load_processed_dataframe
    from ..analytics.charts import vendor_product_chart as vendor_chart
    from ..config import PROCESSED_DATASET_DIR
    from ..rag import RagRetriever
    from .chat import streamlit_chat
except ImportError:
    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from src.analytics import load_processed_dataframe
    from src.analytics.charts import vendor_product_chart as vendor_chart
    from src.config import PROCESSED_DATASET_DIR
    from src.rag import RagRetriever
    from src.app.chat import streamlit_chat


def run_app(dataset_path: Optional[str] = None) -> None:
    """Streamlit 메인 진입점."""

    st.set_page_config(page_title="CVE/CWE Mini Explorer", layout="wide")
    st.title("CVE / CWE 분석 대시보드")
    dataset_path = dataset_path or str(PROCESSED_DATASET_DIR)

    if st.sidebar.button("데이터 다시 불러오기"):
        st.cache_data.clear()

    df = st.cache_data(load_processed_dataframe)(dataset_path)
    st.sidebar.metric("총 CVE 건수", len(df))

    top_n = st.sidebar.slider("Top-N 범위", min_value=5, max_value=30, value=15)
    vendor_summary = vendor_chart.summarize_vendor_counts(df, top_n=top_n)
    product_summary = vendor_chart.summarize_product_counts(df, top_n=top_n)
    vendor_fig = vendor_chart.build_vendor_bar_chart(df, top_n=top_n)
    product_fig = vendor_chart.build_product_bar_chart(df, top_n=top_n)

    vendor_tab, future_tab, chat_tab = st.tabs([
        "벤더/제품 분석",
        "추가 분석(예정)",
        "챗봇",
    ])

    with vendor_tab:
        st.subheader("벤더/제품 CVE 분포")
        st.plotly_chart(vendor_fig, use_container_width=True)
        st.plotly_chart(product_fig, use_container_width=True)
        st.caption("vendor_product_chart.py 모듈에서 반환된 요약 예제")
        col1, col2 = st.columns(2)
        with col1:
            st.write("Top Vendors")
            st.dataframe(vendor_summary)
        with col2:
            st.write("Top Products")
            st.dataframe(product_summary)

    with future_tab:
        st.info("추가 시각화/리포트 페이지가 여기 추가될 예정입니다.")

    with chat_tab:
        retriever = RagRetriever()
        try:
            retriever.load()
        except Exception as exc:  # pragma: no cover - Streamlit 에러 피드백
            st.error(f"RAG 인덱스를 불러오지 못했습니다: {exc}")
        else:
            st.markdown("**예제:** vendor_product_chart 요약 DF를 챗봇 입력으로 사용")
            system_prompt = (
                "당신은 벤더/제품 위험도를 요약하는 보안 분석 어시스턴트입니다."
                " 제공된 요약 DF와 RAG 검색 결과를 바탕으로 리포트를 작성하세요."
            )
            # 예제: vendor_product_chart 결과 DF를 그대로 전달해 요약 시작
            streamlit_chat(
                retriever,
                df=vendor_summary,
                system_prompt=system_prompt,
                session_key="vendor_product_chat",
            )


if __name__ == "__main__":
    run_app()
