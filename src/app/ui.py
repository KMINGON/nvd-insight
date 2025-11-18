from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence, Tuple
import sys

import pandas as pd
import streamlit as st

# 기능: 패키지 실행/스크립트 실행 양쪽에서 공용 모듈을 임포트하기 위한 가드 로직.
try:
    from ..analytics import iter_dataset_files, load_processed_dataframe
    from ..analytics.charts import vendor_product_chart as vendor_chart
    from ..analytics.charts import skr_score
    from ..config import PROCESSED_DATASET_DIR
    from ..rag import RagRetriever
    from .chat import streamlit_chat
except ImportError:
    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from src.analytics import iter_dataset_files, load_processed_dataframe
    from src.analytics.charts import vendor_product_chart as vendor_chart
    from src.analytics.charts import skr_score
    from src.config import PROCESSED_DATASET_DIR
    from src.rag import RagRetriever
    from src.app.chat import streamlit_chat

YEAR_PATTERN = re.compile(r"(\d{4})")


# 기능: 인사이트 페이지 정의를 담는 데이터 클래스.
# 기능: 각 인사이트 페이지 구성을 정의하는 데이터 클래스.
@dataclass
class InsightPage:
    key: str
    label: str
    description: str
    render: Callable[[pd.DataFrame, Tuple[int, ...], Optional[RagRetriever]], None]


# 기능: Streamlit 진입점을 실행해 공통 필터+인사이트 페이지를 렌더링한다.
def run_app(dataset_path: Optional[str] = None) -> None:
    """Streamlit 앱 진입점."""

    st.set_page_config(page_title="CVE/CWE Insight Explorer", layout="wide")
    st.title("CVE / CWE 인사이트 허브")
    dataset_root = dataset_path or str(PROCESSED_DATASET_DIR)

    available_years = discover_available_years(dataset_root)
    if not available_years:
        st.error("처리된 데이터셋을 찾을 수 없습니다. build_dataset.py를 먼저 실행하세요.")
        return

    with st.sidebar:
        st.header("공통 데이터 필터")
        selected_years = st.multiselect(
            "연도 선택",
            options=available_years,
            default=[year for year in available_years if year == 2025] or available_years,
            help="모든 인사이트 페이지에서 동일하게 사용할 연도를 지정합니다.",
        )
        insight_key = st.selectbox(
            "인사이트 선택",
            options=list(INSIGHT_PAGES.keys()),
            format_func=lambda key: INSIGHT_PAGES[key].label,
        )

    years_tuple = tuple(sorted(selected_years))
    if not years_tuple:
        st.warning("최소 한 개 이상의 연도를 선택해야 합니다.")
        return

    df = load_dataset(dataset_root, years_tuple)
    st.sidebar.success(f"{len(df):,} 건 로드 완료")

    retriever = load_retriever()
    page = INSIGHT_PAGES[insight_key]

    st.subheader(page.label)
    st.caption(page.description)
    page.render(df, years_tuple, retriever)


# 기능: 처리된 데이터 디렉터리를 검사해 사용 가능한 연도를 수집한다.
def discover_available_years(dataset_path: str | None) -> list[int]:
    """processed 디렉터리에서 사용 가능한 연도 목록을 추출한다."""
    years: set[int] = set()
    try:
        for path in iter_dataset_files(dataset_path):
            match = YEAR_PATTERN.search(path.stem)
            if match:
                years.add(int(match.group(1)))
    except FileNotFoundError:
        return []
    return sorted(years)


# 기능: 선택된 연도 조합을 캐싱하며 데이터프레임으로 로드한다.
@st.cache_data(show_spinner=False)
def load_dataset(dataset_path: str, years: Tuple[int, ...]) -> pd.DataFrame:
    """선택된 연도 조합을 기반으로 처리된 DF를 로드한다."""
    data_kwargs = {"dataset_path": dataset_path}
    year_seq: Optional[Sequence[int]] = list(years)
    return load_processed_dataframe(years=year_seq, **data_kwargs)


# 기능: RAG 검색기를 초기화하고 인덱스를 읽어온다.
def load_retriever() -> Optional[RagRetriever]:
    """RagRetriever를 초기화하고 로드한다."""
    try:
        retriever = RagRetriever()
        retriever.load()
        return retriever
    except Exception as exc:  # pragma: no cover - UI 피드백 전용
        st.sidebar.warning(f"RAG 검색기를 불러오지 못했습니다: {exc}")
        return None


# 기능: 연도와 파라미터 조합에 따라 Streamlit 세션 키를 생성한다.
def build_session_key(base: str, years: Tuple[int, ...], suffix: str | None = None) -> str:
    """연도/페이지 조합에 맞춘 고유 세션 키를 생성한다."""
    year_part = "-".join(str(year) for year in years) if years else "all"
    key = f"{base}_{year_part}"
    if suffix:
        key = f"{key}_{suffix}"
    return key


# 기능: 벤더/제품 인사이트 페이지의 분석/AI 탭을 렌더링한다.
def render_vendor_product_page(
    df: pd.DataFrame,
    years: Tuple[int, ...],
    retriever: Optional[RagRetriever],
) -> None:
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


# 기능: SKR Score 인사이트 페이지의 분석/AI 탭을 렌더링한다.
def render_skr_score_page(
    df: pd.DataFrame,
    years: Tuple[int, ...],
    retriever: Optional[RagRetriever],
) -> None:
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


INSIGHT_PAGES = {
    "vendor_product": InsightPage(
        key="vendor_product",
        label="벤더/제품 Top-N 인사이트",
        description="벤더와 제품별로 CVE 노출 상위권을 분석하고 RAG 기반 요약을 제공합니다.",
        render=render_vendor_product_page,
    ),
    "skr_score": InsightPage(
        key="skr_score",
        label="SKR Score 기반 고위험 인사이트",
        description="SKR Score가 높은 CVE/벤더/제품/CWE를 다각도로 분석합니다.",
        render=render_skr_score_page,
    ),
}


if __name__ == "__main__":
    run_app()
