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

    # ---------------------------------------------------------
    # 탭 구성
    # ---------------------------------------------------------
    analysis_tab, ai_tab = st.tabs(["분석 시각화", "AI 요약 리포트"])

    # ---------------------------------------------------------
    # 연도별 요약
    # ---------------------------------------------------------
    yearly_summary = trend_charts.summarize_yearly_counts(df)
    available_years = yearly_summary["year"].astype(int).tolist()
    default_focus = "전체 연도"
    if available_years:
        default_focus = str(max(available_years))

    # =========================================================
    # 분석 시각화 탭
    # =========================================================
    with analysis_tab:

        # -------------------------------
        # 초보자용 안내 메시지
        # -------------------------------
        st.info(
            """
            ### 처음 보시는 분들을 위한 간단 설명
            CVE 데이터는 **취약점이 언제 공개되었는지**에 따라 일정한 패턴이 보입니다.  
            아래 그래프들은 다음과 같은 질문에 답할 수 있도록 도와줍니다:

            - **“특정 연도에 취약점이 더 많이 나왔나요?”**  
            - **“어떤 달에 취약점 공개가 몰리는 경향이 있나요?”**  
            - **“계절성(시즌 패턴)이 존재하나요?”**

            이런 패턴들은 **패치 일정, 기술 업계 이벤트, 특정 플랫폼 출시 및 보안 이슈**와 맞물려 나타나는 경우가 많아요.
            """
        )

        st.subheader("전체 기간 분석 요약")
        st.metric("선택된 기간 총 CVE", f"{int(yearly_summary['count'].sum()):,}")

        # -------------------------------
        # 분석 팁: 초보자용
        # -------------------------------
        st.success(
            """
            ### 분석 팁  
            - 숫자가 많아 보일 수 있지만, **연도별 증가/감소 흐름**만 먼저 보면 충분합니다.  
            - 데이터 분석이 익숙하지 않다면 **가장 최근 연도부터 살펴보는 것**을 추천해요.  
            - 월별 그래프는 **특정 시점에 보안 이슈가 몰린 현상**을 확인할 때 효과적입니다.
            """
        )

        # ---------------------------------------------------------
        # 연도 선택
        # ---------------------------------------------------------
        focus_options = ["전체 연도"] + [str(year) for year in available_years]
        focus_year_label = st.selectbox(
            "월별 추이 분석 기준 연도 선택",
            options=focus_options,
            index=focus_options.index(default_focus)
            if default_focus in focus_options else 0,
            help="최근 한 해의 패턴을 보고 싶다면 해당 연도를 선택해보세요!",
        )
        focus_year = None if focus_year_label == "전체 연도" else int(focus_year_label)

        # ---------------------------------------------------------
        # 연도별 전체 추이 그래프
        # ---------------------------------------------------------
        st.markdown("### 연도별 CVE 공개 추이")
        st.caption(
            "이 그래프는 **각 연도마다 CVE가 얼마나 공개되었는지를 보여주는 기본 트렌드 분석**입니다.\n"
            "연도별 증가세·감소세를 확인하면 전체적인 위협 흐름을 파악할 수 있어요."
        )

        yearly_fig = trend_charts.build_yearly_published_trend(df)
        st.plotly_chart(yearly_fig, use_container_width=True)

        # ---------------------------------------------------------
        # 2개 컬럼
        # ---------------------------------------------------------
        col1, col2 = st.columns(2)

        # ---- 왼쪽: 월별 분석
        with col1:
            monthly_title = (
                "전체 월별 Published 추이"
                if focus_year is None
                else f"{focus_year}년 월별 추이"
            )
            st.markdown(f"### {monthly_title}")
            st.caption(
                "월 기준으로 CVE 공개 빈도를 시각화한 그래프입니다. 특정 달에 급증하는 현상은 **업계 보안 이벤트 또는 패치 일정**과 연관될 수 있습니다."
            )

            monthly_fig = trend_charts.build_monthly_published_trend(df, focus_year=focus_year)
            st.plotly_chart(monthly_fig, use_container_width=True)

        # ---- 오른쪽: Heatmap
        with col2:
            st.markdown("### 연도-월 Heatmap (패턴 한눈에 보기)")
            st.caption(
                "연도와 월을 교차하여 CVE 공개 패턴을 색상으로 표시한 Heatmap입니다. 진한 색일수록 **해당 기간에 더 많은 취약점이 발표되었음**을 의미합니다."
            )

            heatmap_fig = trend_charts.build_publication_heatmap(df)
            st.plotly_chart(heatmap_fig, use_container_width=True)

        # -------------------------------
        # 활용 예시 (입문자용)
        # -------------------------------
        st.info(
            """
            ### 이렇게 활용해보세요!
            - **과제/발표** → “2023년은 평균 대비 취약점이 크게 증가했다” 같은 인사이트 만들기  
            - **보안 교육 자료** → 특정 연도 또는 특정 달에 집중된 이상치 강조하기  
            - **포트폴리오** → 트렌드 기반 분석 그래프를 그대로 첨부 가능  
            - **기초 학습** → ‘CVE 공개는 무작위가 아니다’라는 개념 이해에 도움
            """
        )

    # =========================================================
    # AI 자동 분석 탭
    # =========================================================
    with ai_tab:
        if retriever is None:
            st.info("RAG 검색기를 사용할 수 없습니다. 인덱스 상태를 확인하세요.")
            return

        # context 데이터 선정
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
