from __future__ import annotations

from typing import Optional, Tuple

import pandas as pd
import streamlit as st

from src.analytics.charts import cwe as cwe_chart
from src.rag import RagRetriever
from ..chat import streamlit_chat
from ..common import build_session_key


def render_cwe_page(
    df: pd.DataFrame,
    years: Tuple[int, ...],
    retriever: Optional[RagRetriever],
) -> None:
    """CWE Top-N 분포를 시각화하고 챗봇 요약을 제공한다."""

    analysis_tab, ai_tab = st.tabs(["분석 시각화", "AI 요약 리포트"])
    cwe_summary: Optional[pd.DataFrame] = None
    top_n = 20

    with analysis_tab:
        top_n = st.slider("CWE Top-N 범위", min_value=5, max_value=50, value=20, step=5)
        try:
            cwe_summary = cwe_chart.summarize_cwe_counts(df, top_n=top_n)
            fig = cwe_chart.build_cwe_top_chart(df, top_n=top_n)
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(cwe_summary)
        except Exception as exc:
            st.warning(f"CWE 데이터를 불러올 수 없습니다: {exc}")

    with ai_tab:
        if retriever is None:
            st.info("RAG 검색기를 사용할 수 없습니다. 인덱스 상태를 확인하세요.")
            return
        if cwe_summary is None or cwe_summary.empty:
            st.info("CWE 요약 데이터가 없어 챗봇을 실행할 수 없습니다.")
            return
        system_prompt = (
            "당신은 CWE 취약점 유형 빈도를 분석하는 한국어 보안 분석가입니다. "
            "Top-N CWE 목록을 기반으로 조직이 우선순위를 둬야 할 방어 영역을 설명하세요."
        )
        session_key = build_session_key("cwe_insight", years, suffix=f"top{top_n}")
        streamlit_chat(
            retriever,
            df=cwe_summary,
            system_prompt=system_prompt,
            session_key=session_key,
        )
