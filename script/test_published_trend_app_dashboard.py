from __future__ import annotations

import re
from typing import List, Optional, Sequence

from pathlib import Path
import sys

import pandas as pd
import streamlit as st

# -------------------------------------------------------------------
# 📌 프로젝트 루트 경로 계산 후, Python 모듈 탐색 경로(sys.path)에 추가
#    (Streamlit 실행 시 상대 경로 문제를 방지하기 위한 처리)
# -------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 프로젝트 내부 모듈 로딩
from src.analytics.base_loader import iter_dataset_files, load_processed_dataframe
from src.analytics.charts import published_trend_app as trend_charts


# -------------------------------------------------------------------
# 📌 처리된 데이터셋 파일 목록에서 사용 가능한 “연도”를 추출하는 함수
#    (파일명 끝에 붙은 4자리 연도 정규식 사용)
# -------------------------------------------------------------------
def discover_available_years() -> List[int]:
    """
    처리된 dataset 파일들의 연도 목록을 추출하여 리스트로 반환한다.
    파일명 예: processed-2023.pkl → year=2023
    """
    year_pattern = re.compile(r"(\d{4})$")   # 끝 4자리 숫자(연도) 추출
    years: set[int] = set()

    for dataset_path in iter_dataset_files():
        match = year_pattern.search(dataset_path.stem)
        if match:
            years.add(int(match.group(1)))

    return sorted(years)


# -------------------------------------------------------------------
# 📌 선택된 연도(years)에 해당하는 데이터셋을 불러오는 함수
#    load_processed_dataframe 래퍼(wrapper)
# -------------------------------------------------------------------
def load_dataset(years: Sequence[int]) -> pd.DataFrame:
    """
    연도 리스트를 입력받아 해당 연도들의 데이터셋을 로딩한다.
    """
    if not years:
        raise ValueError("At least one year must be selected to load the dataset.")
    return load_processed_dataframe(years=years)


# -------------------------------------------------------------------
# 📌 Plotly 또는 Altair 차트를 Streamlit에서 자동 렌더링하는 헬퍼 함수
# -------------------------------------------------------------------
def render_figure(figure) -> None:
    """
    Plotly / Altair 객체를 자동 판별하여 Streamlit에 렌더링한다.
    """
    if hasattr(figure, "to_plotly_json"):      # Plotly figure
        st.plotly_chart(figure, use_container_width=True)
    elif hasattr(figure, "to_dict"):           # Altair figure
        st.altair_chart(figure, use_container_width=True)
    else:
        st.write("지원되지 않는 차트 형식입니다.", figure)


# -------------------------------------------------------------------
# 📌 메인 Streamlit 앱
# -------------------------------------------------------------------
def main() -> None:
    # 페이지 설정
    st.set_page_config(page_title="Published Trend Test Dashboard", layout="wide")
    st.title("Published Trend 모듈 테스트")

    # ----------------------
    # 📌 Sidebar - 데이터 선택 옵션
    # ----------------------
    with st.sidebar:
        st.header("데이터 필터")

        # 사용 가능한 연도 목록 로드
        available_years = discover_available_years()

        if not available_years:
            st.error("처리된 데이터셋을 찾을 수 없습니다. build_dataset.py를 먼저 실행하세요.")
            st.stop()

        # 분석에 포함할 연도 선택 (멀티 선택)
        year_selection = st.multiselect(
            "연도 선택",
            options=available_years,
            default=available_years,    # 기본값: 모든 연도 선택
            help="분석에 포함할 연도를 선택하세요.",
        )

        # 월별 그래프를 특정 연도 기준으로 보고 싶을 때
        focus_year_label = st.selectbox(
            "월별 차트 기준 연도",
            options=["전체 연도"] + [str(year) for year in available_years],
            index=0,
        )
        # "전체 연도"일 경우 None, 그 외 연도는 int 변환
        focus_year: Optional[int] = None if focus_year_label == "전체 연도" else int(focus_year_label)

    # 연도 선택 안 했으면 중단
    if not year_selection:
        st.warning("최소 한 개 이상의 연도를 선택해야 합니다.")
        st.stop()

    # ----------------------
    # 📌 데이터 로딩
    # ----------------------
    try:
        df = load_dataset(year_selection)
    except Exception as exc:  # 크게 발생하기 쉬운 에러는 여기서 잡힘
        st.error(f"데이터 로딩 실패: {exc}")
        st.stop()

    st.sidebar.success(f"{len(df):,} 건 로드 완료")
    st.metric("총 CVE 레코드", f"{len(df):,}")

    # ----------------------
    # 📌 대시보드 탭 구성
    # ----------------------
    tabs = st.tabs(["연도별 추이", "월별 추이", "연도-월 Heatmap"])

    # ----------------------
    # 탭 1) 연도별 트렌드
    # ----------------------
    with tabs[0]:
        st.subheader("연도별 Published 추이")
        fig_yearly = trend_charts.build_yearly_published_trend(df)
        render_figure(fig_yearly)

    # ----------------------
    # 탭 2) 월별 트렌드
    # ----------------------
    with tabs[1]:
        st.subheader("월별 Published 추이")
        fig_monthly = trend_charts.build_monthly_published_trend(df, focus_year=focus_year)
        render_figure(fig_monthly)

    # ----------------------
    # 탭 3) 연도-월 Heatmap
    # ----------------------
    with tabs[2]:
        st.subheader("연도-월 Heatmap")
        fig_heatmap = trend_charts.build_publication_heatmap(df)
        render_figure(fig_heatmap)


# -------------------------------------------------------------------
# 📌 Streamlit 실행 진입점
# -------------------------------------------------------------------
if __name__ == "__main__":
    main()
