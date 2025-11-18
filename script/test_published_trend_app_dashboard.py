from __future__ import annotations

import re
from typing import List

import pandas as pd
import streamlit as st

# 프로젝트 내부의 데이터 로딩 모듈들
from src.analytics.base_loader import (
    iter_dataset_files,
    load_processed_dataframe,
)
from src.analytics.charts import published_trend_app


# ================================
#   사용 가능한 연도 자동 탐색
# ================================
def discover_available_years() -> List[int]:
    """
    처리된 데이터셋 파일 이름을 분석하여
    포함된 연도를 자동으로 추출해 정렬된 리스트로 반환.
    (예: processed_cve_2023.parquet → 2023)
    """
    year_pattern = re.compile(r"(\d{4})$")  # 파일명 끝의 4자리 연도 추출
    years: set[int] = set()

    # data/processed/ 폴더 내의 모든 파일 탐색
    for dataset_path in iter_dataset_files():
        match = year_pattern.search(dataset_path.stem)
        if match:
            years.add(int(match.group(1)))

    return sorted(years)


# ================================
#   published_trend_app 에 맞게 가공
# ================================
def prepare_published_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    processed 데이터셋을 published_trend_app 모듈에서 요구하는 형식으로 정규화.
    주요 작업:
      - published 컬럼 존재 여부 확인
      - datetime 변환
      - year/month 컬럼 생성
    """

    if "published" not in df.columns:
        raise ValueError("Processed dataset does not expose a 'published' column.")

    # published와 함께 필요한 최소한의 컬럼만 선택
    columns: List[str] = ["published"]
    if "cveId" in df.columns:
        columns.insert(0, "cveId")  # 있으면 앞에 추가

    prepared = df[columns].copy()

    # 문자열 → datetime 변환
    prepared["published"] = pd.to_datetime(prepared["published"], errors="coerce")

    # published 값이 없는 행 제거
    prepared = prepared.dropna(subset=["published"])

    # 연도/월 집계를 위한 편의 컬럼 생성
    prepared["year"] = prepared["published"].dt.to_period("Y").dt.to_timestamp()
    prepared["month"] = prepared["published"].dt.to_period("M").dt.to_timestamp()

    return prepared


# ================================
#     Plotly 또는 Altair 자동 렌더링
# ================================
def render_chart(figure) -> None:
    """
    차트 객체의 타입을 검사한 후,
    Plotly 또는 Altair 로 적절하게 렌더링.
    """

    # Plotly 그래프인지 확인
    if hasattr(figure, "to_plotly_json"):
        st.plotly_chart(figure, use_container_width=True)

    # Altair인지 확인
    elif hasattr(figure, "to_dict"):
        st.altair_chart(figure, use_container_width=True)

    else:
        st.write("지원되지 않는 차트 형식입니다.", figure)


# ================================
#          Streamlit 메인
# ================================
def main() -> None:
    # 페이지 기본 설정
    st.set_page_config(
        page_title="Published Trend Test Dashboard",
        layout="wide",
    )
    st.title("Published Trend 모듈 테스트")

    # ---- 사이드바에서 연도 필터 구성 ----
    with st.sidebar:
        st.header("데이터 필터")

        # 처리된 데이터셋을 기반으로 사용 가능한 연도 자동 탐색
        available_years = discover_available_years()

        selection_help = "분석에 포함할 연도를 선택하세요."

        year_selection = st.multiselect(
            "연도 선택",
            options=available_years,
            default=available_years,  # 기본: 모든 연도 선택
            help=selection_help,
        )

    # ---- 데이터 로드 ----
    try:
        # 특정 연도만 불러오기 (None이면 전체 로드)
        processed_df = load_processed_dataframe(
            years=year_selection or None,
        )
    except Exception as exc:  # 예외 발생 시 Streamlit 에러 표시
        st.error(f"데이터를 불러오는데 실패했습니다: {exc}")
        st.stop()

    # ---- published 컬럼 가공 ----
    published_df = prepare_published_dataframe(processed_df)

    if published_df.empty:
        st.warning("선택된 조건에 해당하는 published 데이터가 없습니다.")
        st.stop()

    # 총 CVE 개수 메트릭 출력
    st.metric("CVE 건수", f"{len(published_df):,}")

    # ---- 탭 구성: 연도별 / 월별 ----
    tabs = st.tabs(["연도별 추이", "월별 추이"])

    # 연도별 그래프
    with tabs[0]:
        st.subheader("연도별 Published 추이")
        figure = published_trend_app.plot_counts(published_df, granularity="year")
        render_chart(figure)

    # 월별 그래프
    with tabs[1]:
        st.subheader("월별 Published 추이")
        figure = published_trend_app.plot_counts(published_df, granularity="month")
        render_chart(figure)


# 실행 진입점
if __name__ == "__main__":
    main()
