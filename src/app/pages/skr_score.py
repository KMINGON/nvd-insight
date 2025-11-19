from __future__ import annotations

from typing import Optional, Tuple

import pandas as pd
import streamlit as st

from src.analytics.charts import skr_score
from src.rag import RagRetriever
from ..chat import streamlit_chat
from ..common import build_session_key


def render_skr_score_page(
    df: pd.DataFrame,
    years: Tuple[int, ...],
    retriever: Optional[RagRetriever],
) -> None:
    """SKR Score 인사이트 페이지의 슬라이더, 차트, AI 요약 탭을 렌더링한다."""

    analysis_tab, ai_tab = st.tabs(["분석 시각화", "AI 요약 리포트"])
    with analysis_tab:
        st.markdown("**SKR Score 인사이트 파라미터**")
        score_threshold = st.slider(
            "SKR Score 최소값",
            min_value=5.0,
            max_value=9.5,
            value=7.0,
            step=0.5,
            key="skr_threshold_slider",
        )
        top_n = st.slider("Top-N 범위 (벤더/제품/CWE)", min_value=5, max_value=20, value=10, key="skr_topn_slider")
        enriched = skr_score.build_skr_score_added_df(df)
        top10_df = skr_score.build_top10_dataset(source_df=enriched)
        vendor_summary = skr_score.summarize_vendor_counts(enriched, top_n=top_n, threshold=score_threshold)
        product_summary = skr_score.summarize_product_counts(enriched, top_n=top_n, threshold=score_threshold)
        cwe_summary = skr_score.summarize_cwe_scores(enriched, top_n=top_n, threshold=score_threshold)

        st.plotly_chart(skr_score.build_top10_chart(top10_df), use_container_width=True)
        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(
                skr_score.build_vendor_score_chart(vendor_summary, "SKR 고위험 벤더"),
                use_container_width=True,
            )
            st.dataframe(vendor_summary)
        with col2:
            st.plotly_chart(
                skr_score.build_product_score_chart(product_summary, "SKR 고위험 제품"),
                use_container_width=True,
            )
            st.dataframe(product_summary)

        st.plotly_chart(
            skr_score.build_cwe_score_chart(cwe_summary, "SKR 고위험 CWE"),
            use_container_width=True,
        )
        st.dataframe(cwe_summary)

    with ai_tab:
        if retriever is None:
            st.info("RAG 검색기를 사용할 수 없습니다. 인덱스 상태를 확인하세요.")
            return
        system_prompt = (
            "당신은 SKR Score 기반으로 고위험 CVE를 선별하는 한국어 보안 분석가입니다. "
            "반드시 한국어로 답변하며, Top10 CVE와 고위험 벤더/제품/CWE 집계를 바탕으로 위험 요인을 요약하세요."
        )
        session_key = build_session_key("skr_insight", years, suffix=f"thr{score_threshold}")
        streamlit_chat(
            retriever,
            df=top10_df,
            system_prompt=system_prompt,
            session_key=session_key,
        )
