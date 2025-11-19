from __future__ import annotations

from typing import Optional, Tuple

import pandas as pd
import streamlit as st

from src.analytics.charts import vendor_product_chart as vendor_chart
from src.rag import RagRetriever
from ..chat import streamlit_chat
from ..common import build_session_key


def render_vendor_product_page(
    df: pd.DataFrame,
    years: Tuple[int, ...],
    retriever: Optional[RagRetriever],
) -> None:
    """벤더/제품 인사이트 페이지의 분석/AI 탭을 렌더링한다."""

    analysis_tab, ai_tab = st.tabs(["분석 시각화", "AI 요약 리포트"])

    with analysis_tab:
        top_n = st.slider("Top-N 범위", min_value=5, max_value=30, value=15, key="vendor_topn_slider")
        vendor_summary = vendor_chart.summarize_vendor_counts(df, top_n=top_n)
        product_summary = vendor_chart.summarize_product_counts(df, top_n=top_n)
        vendor_fig = vendor_chart.build_vendor_bar_chart(df, top_n=top_n)
        product_fig = vendor_chart.build_product_bar_chart(df, top_n=top_n)

        st.plotly_chart(vendor_fig, use_container_width=True)
        st.plotly_chart(product_fig, use_container_width=True)
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Top Vendors**")
            st.dataframe(vendor_summary)
        with col2:
            st.markdown("**Top Products**")
            st.dataframe(product_summary)

    with ai_tab:
        if retriever is None:
            st.info("RAG 검색기를 사용할 수 없습니다. 인덱스 상태를 확인하세요.")
            return
        system_prompt = (
            "당신은 벤더/제품 CVE 분포를 요약하는 한국어 보안 분석가입니다. "
            "반드시 한국어로 답변하며, 제공된 Top-N 요약과 RAG 검색 결과를 결합해 주요 위험 벤더/제품을 설명하세요."
        )
        session_key = build_session_key("vendor_insight", years, suffix=f"top{top_n}")
        streamlit_chat(
            retriever,
            df=vendor_summary,
            system_prompt=system_prompt,
            session_key=session_key,
        )
