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


@dataclass
class InsightPage:
    """UI에서 하나의 인사이트 페이지 구성을 정의한다.

    속성:
        key: 위젯/세션 키에 사용되는 고유 식별자.
        label: 탭과 헤더에 노출되는 사용자 친화적 이름.
        description: 헤더 아래에 표시할 짧은 설명.
        render: 시각화 탭과 RAG 탭을 모두 그리는 콜백 함수.
    """

    key: str
    label: str
    description: str
    render: Callable[[pd.DataFrame, Tuple[int, ...], Optional[RagRetriever]], None]


# 기능: Streamlit 진입점을 실행해 공통 필터+인사이트 페이지를 렌더링한다.
def run_app(dataset_path: Optional[str] = None) -> None:
    """Streamlit UI를 실행하고 데이터셋을 로드해 선택된 인사이트로 라우팅한다.

    매개변수:
        dataset_path: 처리된 JSON 파일이 있는 디렉터리를 덮어쓰는 경로.

    반환값:
        없음. Streamlit 전면에 직접 렌더링한다.
    """

    # Streamlit 페이지 전역 설정: 제목과 레이아웃을 가장 먼저 지정한다.
    st.set_page_config(page_title="CVE/CWE Insight Explorer", layout="wide")
    st.title("CVE / CWE 인사이트 허브")
    # 외부에서 경로를 넘기지 않으면 config에 정의된 기본 경로를 사용한다.
    dataset_root = dataset_path or str(PROCESSED_DATASET_DIR)

    # 실제로 존재하는 연도만을 필터 옵션으로 보여주기 위해 먼저 스캔한다.
    available_years = discover_available_years(dataset_root)
    if not available_years:
        st.error("처리된 데이터셋을 찾을 수 없습니다. build_dataset.py를 먼저 실행하세요.")
        return

    with st.sidebar:
        st.header("공통 데이터 필터")
        # 기본 필터는 2025가 있으면 그 연도만, 없으면 전체 연도다.
        selected_years = st.multiselect(
            "연도 선택",
            options=available_years,
            default=[year for year in available_years if year == 2025] or available_years,
            help="모든 인사이트 페이지에서 동일하게 사용할 연도를 지정합니다.",
        )
        # InsightPage 레지스트리에 등록된 키를 그대로 드롭다운으로 노출한다.
        insight_key = st.selectbox(
            "인사이트 선택",
            options=list(INSIGHT_PAGES.keys()),
            format_func=lambda key: INSIGHT_PAGES[key].label,
        )

    # 다중 선택 결과를 정렬해 튜플로 저장하면 캐싱 키와 세션 키 모두 안정적으로 구성된다.
    years_tuple = tuple(sorted(selected_years))
    if not years_tuple:
        st.warning("최소 한 개 이상의 연도를 선택해야 합니다.")
        return

    # 연도 튜플이 캐시 키로 활용되므로 동일 조합에서 중복 로딩을 피할 수 있다.
    df = load_dataset(dataset_root, years_tuple)
    st.sidebar.success(f"{len(df):,} 건 로드 완료")

    # 챗봇 탭이 활성화되면 공통 retriever를 재사용하므로 여기서 한 번만 불러온다.
    retriever = load_retriever()
    page = INSIGHT_PAGES[insight_key]

    # InsightPage 정의로부터 제목/설명을 읽어 표시하고 렌더 콜백을 호출한다.
    st.subheader(page.label)
    st.caption(page.description)
    page.render(df, years_tuple, retriever)


# 기능: 처리된 데이터 디렉터리를 검사해 사용 가능한 연도를 수집한다.
def discover_available_years(dataset_path: str | None) -> list[int]:
    """처리된 데이터셋 디렉터리를 살펴보고 파일명에서 연도 정보를 추출한다.

    매개변수:
        dataset_path: 처리된 JSON 샤드가 들어 있는 디렉터리.

    반환값:
        파일명에서 추출한 연도의 정렬된 리스트. 경로가 없으면 빈 리스트.
    """
    years: set[int] = set()
    try:
        # 처리된 JSON 파일명을 하나씩 순회하며 연도 패턴을 추출한다.
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
    """선택한 연도 튜플에 맞는 처리된 데이터프레임을 로드하고 캐시한다.

    매개변수:
        dataset_path: 처리된 JSON 파일이 저장된 기본 디렉터리.
        years: 사이드바에서 선택한 연도 튜플(캐시 키/쿼리에 사용).

    반환값:
        지정한 연도에 해당하는 모든 행을 포함한 DataFrame.
    """
    data_kwargs = {"dataset_path": dataset_path}
    # 캐시에서 튜플을 그대로 쓸 수 있지만 downstream 함수는 시퀀스를 기대하므로 리스트로 변환한다.
    year_seq: Optional[Sequence[int]] = list(years)
    return load_processed_dataframe(years=year_seq, **data_kwargs)


# 기능: RAG 검색기를 초기화하고 인덱스를 읽어온다.
def load_retriever() -> Optional[RagRetriever]:
    """RagRetriever를 생성하고 FAISS 인덱스를 로드해 실패 시 사용자에게 알린다.

    반환값:
        초기화된 RagRetriever 인스턴스 혹은 실패 시 None.
    """
    try:
        retriever = RagRetriever()
        # load 호출 시 실제 FAISS 파일이 없으면 예외가 발생하므로 UI에 바로 피드백한다.
        retriever.load()
        return retriever
    except Exception as exc:  # pragma: no cover - UI 피드백 전용
        st.sidebar.warning(f"RAG 검색기를 불러오지 못했습니다: {exc}")
        return None


# 기능: 연도와 파라미터 조합에 따라 Streamlit 세션 키를 생성한다.
def build_session_key(base: str, years: Tuple[int, ...], suffix: str | None = None) -> str:
    """페이지/연도 조합에 해당하는 채팅 히스토리 세션 키를 생성한다.

    매개변수:
        base: 인사이트 키 등 기본 네임스페이스.
        years: 챗봇 세션 캐시에 영향을 주는 연도 튜플.
        suffix: 슬라이더 설정처럼 추가 식별이 필요한 경우의 접미사.

    반환값:
        st.session_state에서 재사용 가능한 고유 키.
    """
    year_part = "-".join(str(year) for year in years) if years else "all"
    key = f"{base}_{year_part}"
    if suffix:
        # 슬라이더 값 등 추가 식별자가 필요한 경우 접미사를 붙인다.
        key = f"{key}_{suffix}"
    return key


# 기능: 벤더/제품 인사이트 페이지의 분석/AI 탭을 렌더링한다.
def render_vendor_product_page(
    df: pd.DataFrame,
    years: Tuple[int, ...],
    retriever: Optional[RagRetriever],
) -> None:
    """벤더/제품 인사이트 페이지의 시각화 탭과 RAG 탭을 모두 렌더링한다.

    매개변수:
        df: 선택된 연도로 필터링된 처리 데이터프레임.
        years: 현재 선택된 연도 튜플.
        retriever: AI 요약 탭에서 사용할 RAG 검색기.

    반환값:
        없음. 탭 내용을 Streamlit에 직접 작성한다.
    """
    analysis_tab, ai_tab = st.tabs(["분석 시각화", "AI 요약 리포트"])

    with analysis_tab:
        # 사용자가 벤더/제품 상위 랭크 범위를 즉시 조정할 수 있도록 슬라이더를 노출한다.
        top_n = st.slider("Top-N 범위", min_value=5, max_value=30, value=15, key="vendor_topn_slider")
        # chart 모듈이 제공하는 요약 함수를 이용해 벤더/제품 상위 리스트를 얻는다.
        vendor_summary = vendor_chart.summarize_vendor_counts(df, top_n=top_n)
        product_summary = vendor_chart.summarize_product_counts(df, top_n=top_n)
        vendor_fig = vendor_chart.build_vendor_bar_chart(df, top_n=top_n)
        product_fig = vendor_chart.build_product_bar_chart(df, top_n=top_n)

        # Plotly 차트 두 개를 세로로 배치해 분포 추이를 시각화한다.
        st.plotly_chart(vendor_fig, use_container_width=True)
        st.plotly_chart(product_fig, use_container_width=True)
        # 텍스트 기반 테이블은 두 개의 column 컨테이너에 병렬로 표시한다.
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Top Vendors**")
            st.dataframe(vendor_summary)
        with col2:
            st.markdown("**Top Products**")
            st.dataframe(product_summary)

    with ai_tab:
        # 동일한 벤더/제품 요약 표를 근거로 RAG 챗봇에게 한국어 보고서를 요청한다.
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
    """SKR Score 인사이트 페이지의 슬라이더, 차트, AI 요약 탭을 렌더링한다.

    매개변수:
        df: 선택된 연도로 필터링된 처리 데이터프레임.
        years: 현재 범위에 포함된 연도 튜플.
        retriever: 인사이트 간 공유되는 RAG 검색기.

    반환값:
        없음.
    """
    analysis_tab, ai_tab = st.tabs(["분석 시각화", "AI 요약 리포트"])
    with analysis_tab:
        st.markdown("**SKR Score 인사이트 파라미터**")
        # SKR Score는 연속형 지표이므로 임계값과 Top-N을 개별로 조정할 수 있게 한다.
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
        # 동일한 필터 조건을 사용해 벤더/제품/CWE 요약을 한 번에 계산한다.
        top10_df = skr_score.build_top10_dataset(source_df=enriched)
        vendor_summary = skr_score.summarize_vendor_counts(enriched, top_n=top_n, threshold=score_threshold)
        product_summary = skr_score.summarize_product_counts(enriched, top_n=top_n, threshold=score_threshold)
        cwe_summary = skr_score.summarize_cwe_scores(enriched, top_n=top_n, threshold=score_threshold)

        # Top10 CVE 분포를 먼저 보여주고 아래에는 벤더/제품/CWE 상세 차트를 배치한다.
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

        # CWE 분석은 별도의 전체 폭 차트로 보여주고 테이블도 바로 아래에 추가한다.
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
