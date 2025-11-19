from __future__ import annotations

from typing import Optional, Tuple

import pandas as pd
import streamlit as st

from src.analytics.charts import published_trend_app as trend_charts
from src.rag import RagRetriever
from ..chat import streamlit_chat
from ..common import build_session_key


def render_published_trend_page(
    df: pd.DataFrame,
    years: Tuple[int, ...],
    retriever: Optional[RagRetriever],
) -> None:
    """공개일 기반 시계열 인사이트 페이지를 렌더링한다."""

    analysis_tab, ai_tab = st.tabs(["분석 시각화", "AI 요약 리포트"])
    yearly_summary = trend_charts.summarize_yearly_counts(df)
    available_years = yearly_summary["year"].astype(int).tolist()
    default_focus = "전체 연도"
    if available_years:
        default_focus = str(max(available_years))

    with analysis_tab:
        st.metric("선택된 기간 총 CVE", f"{int(yearly_summary['count'].sum()):,}")
        focus_options = ["전체 연도"] + [str(year) for year in available_years]
        focus_year_label = st.selectbox(
            "월별 추이 기준 연도",
            options=focus_options,
            index=focus_options.index(default_focus) if default_focus in focus_options else 0,
            help="최근 연도 계절성을 보거나 전체 시즌 패턴을 확인할 수 있습니다.",
        )
        focus_year = None if focus_year_label == "전체 연도" else int(focus_year_label)

        yearly_fig = trend_charts.build_yearly_published_trend(df)
        st.plotly_chart(yearly_fig, use_container_width=True)

        col1, col2 = st.columns(2)
        with col1:
            monthly_title = "월별 Published 추이" if focus_year is None else f"{focus_year}년 월별 추이"
            st.markdown(f"**{monthly_title}**")
            monthly_fig = trend_charts.build_monthly_published_trend(df, focus_year=focus_year)
            st.plotly_chart(monthly_fig, use_container_width=True)
        with col2:
            st.markdown("**연도-월 Heatmap**")
            heatmap_fig = trend_charts.build_publication_heatmap(df)
            st.plotly_chart(heatmap_fig, use_container_width=True)

    with ai_tab:
        if retriever is None:
            st.info("RAG 검색기를 사용할 수 없습니다. 인덱스 상태를 확인하세요.")
            return
        context_df = yearly_summary
        if focus_year is not None:
            monthly_summary = trend_charts.summarize_monthly_counts(df, year=focus_year)
            monthly_summary["year"] = focus_year
            context_df = monthly_summary
        system_prompt = (
            "당신은 CVE 공개 시점 트렌드를 분석하는 한국어 보안 분석가입니다. "
            "연도/월별 변동성과 스파이크, 계절 패턴을 짚어주고 주요 이상 구간이 있으면 근거를 들어 설명하세요."
        )
        session_key = build_session_key("published_trend", years, suffix=f"focus{focus_year or 'all'}")
        streamlit_chat(
            retriever,
            df=context_df,
            system_prompt=system_prompt,
            session_key=session_key,
        )
