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

        persona_configs = {
            "beginner": {
                "label": "입문자용",
                "description": "CWE 코드가 의미하는 취약점 유형과 학습 우선순위를 알려줍니다.",
                "instructions": (
                    "CWE가 취약점 유형을 식별하는 코드라는 점을 쉽게 설명하고, "
                    "그래프 상위에 있는 CWE부터 어떤 순서로 공부하면 좋을지 안내하세요. "
                    "예시로 CWE-79, CWE-89 같은 주요 항목을 언급하며 "
                    "각 유형이 어떤 공격 패턴인지 한두 문장으로 정리해 주세요."
                ),
            },
            "project": {
                "label": "프로젝트용",
                "description": "보고서/포트폴리오에 넣을 인사이트와 프로젝트 아이디어를 제공합니다.",
                "instructions": (
                    "Top-N 테이블과 차트를 근거로 취약점 유형 분포 인사이트를 설명하고, "
                    "보고서나 포트폴리오에 바로 쓸 수 있는 문장을 만들어 주세요. "
                    "또한 어떤 프로젝트(예: 특정 벤더/연도 필터링, OWASP Top 10 비교)로 확장하면 좋을지 "
                    "데이터 연계 아이디어를 1~2개 제시하세요."
                ),
            },
            "instructor": {
                "label": "강사용",
                "description": "강의 포인트와 토론 질문/과제 아이디어를 제안합니다.",
                "instructions": (
                    "실제 수업에서 사용할 통계 예시로서 차트를 설명하고, "
                    "OWASP Top 10 같은 이론과 연결할 수 있는 메시지를 정리하세요. "
                    "학생에게 던질 토론 질문이나 과제 아이디어를 2개 이상 제시하고, "
                    "왜 해당 CWE가 반복되는지 생각해볼 수 있도록 유도해 주세요."
                ),
            },
        }
        # 차트는 같더라도 대상자별로 다른 리포트를 뽑을 수 있도록 페르소나 라디오 버튼 제공
        persona_key = st.radio(
            "AI 리포트 유형",
            options=list(persona_configs.keys()),
            format_func=lambda key: persona_configs[key]["label"],
            horizontal=True,
        )
        st.caption(persona_configs[persona_key]["description"])

        # 기본 설명 프롬프트에 선택된 페르소나용 추가 지침을 결합해 목적별 문장을 생성
        base_prompt = (
            "당신은 CWE 취약점 유형 빈도를 분석하는 한국어 보안 분석가입니다. "
            "Top-N CWE 목록을 활용해 자주 등장하는 취약점 패턴과 그 의미를 설명하세요."
        )
        system_prompt = f"{base_prompt}\n\n{persona_configs[persona_key]['instructions']}"

        session_key = build_session_key(
            "cwe_insight",
            years,
            suffix=f"top{top_n}_{persona_key}",
        )
        streamlit_chat(
            retriever,
            df=cwe_summary,
            system_prompt=system_prompt,
            session_key=session_key,
        )
