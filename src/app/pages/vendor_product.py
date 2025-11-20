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
    """
    벤더/제품 인사이트 페이지 (초보자 친화 UI 적용)
    """

    # ---------------------------------------------------------
    # 탭 구성
    # ---------------------------------------------------------
    analysis_tab, ai_tab = st.tabs(["분석 시각화", "AI 요약 리포트"])

    # ---------------------------------------------------------
    # 분석 시각화 탭
    # ---------------------------------------------------------
    with analysis_tab:

        st.subheader("Vendor / Product 취약점 분포 분석")

        # 초보자 안내 문구
        st.info(
            "**Tip:** Vendor는 회사(예: Microsoft, Adobe), Product는 제품(예: Windows, Chrome)을 의미합니다.\n"
            "어떤 회사·제품에서 취약점이 많이 나오는지 분석하면 학습·보안 대응 우선순위를 잡는 데 큰 도움이 됩니다!"
        )

        # ---------------------------------------------------------
        # Top-N 슬라이더
        # ---------------------------------------------------------
        top_n = st.slider(
            "분석할 상위 개수 선택 (Top-N)",
            min_value=5,
            max_value=30,
            value=15,
            key="vendor_topn_slider",
            help="상위 N개의 Vendor/Product를 확인할 수 있습니다.",
        )

        # ---------------------------------------------------------
        # Summary 계산
        # ---------------------------------------------------------
        vendor_summary = vendor_chart.summarize_vendor_counts(df, top_n=top_n)
        product_summary = vendor_chart.summarize_product_counts(df, top_n=top_n)

        # ---------------------------------------------------------
        # 그래프 2개 표시
        # ---------------------------------------------------------
        st.markdown("### Vendor(회사)별 취약점 Top-N")
        vendor_fig = vendor_chart.build_vendor_bar_chart(df, top_n=top_n)
        st.plotly_chart(vendor_fig, use_container_width=True)
        st.caption("※ 특정 회사의 제품군 전체에서 몇 개의 CVE가 보고되었는지 나타냅니다.")

        st.markdown("### Product(제품)별 취약점 Top-N")
        product_fig = vendor_chart.build_product_bar_chart(df, top_n=top_n)
        st.plotly_chart(product_fig, use_container_width=True)
        st.caption("※ 제품 단위로 어떤 소프트웨어에서 취약점이 많이 보고되는지 보여줍니다.")

        # ---------------------------------------------------------
        # 표 제공 (초보자용 해설)
        # ---------------------------------------------------------
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("### Top Vendor 목록")
            st.dataframe(vendor_summary)
            st.caption("여기서 CVE Count는 해당 회사 제품 전체에서 발견된 CVE 개수입니다.")

        with col2:
            st.markdown("### Top Product 목록")
            st.dataframe(product_summary)
            st.caption("어떤 제품이 보안 이슈에 자주 등장하는지 파악할 수 있어요!")

        # 추가 초보자 해설 영역
        st.info(
            "**활용 예시:**\n"
            "- 보안 학습 → 어떤 회사·제품이 취약점이 많은지 우선 공부할 수 있습니다.\n"
            "- 포트폴리오 작성 → 상위 Vendor/Product 비교 그래프를 활용해 주제 명확화 가능.\n"
            "- 기업 교육 → 특정 벤더 중심 교육 준비에 활용 가능."
        )

    # ---------------------------------------------------------
    # AI 자동 리포트 탭
    # ---------------------------------------------------------
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
