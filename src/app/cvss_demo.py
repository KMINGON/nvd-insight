from __future__ import annotations

import re
from typing import List, Optional, Sequence

import pandas as pd
import streamlit as st

# 패키지 설치 없이도
# `streamlit run src/app/cvss_demo.py` 로 실행할 수 있게
# 프로젝트 루트를 sys.path에 동적으로 추가
import sys
from pathlib import Path

# 현재 파일 기준으로 프로젝트 루트 계산 (상위 2단계)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 전처리된 데이터셋 로더와 연도별 파일 이터레이터
from src.analytics.base_loader import iter_dataset_files, load_processed_dataframe

# 앞에서 만든 차트 유틸 함수들 import
from src.analytics.charts import (
    build_cwe_top_chart,
    build_cvss_score_bin_chart,
    build_cvss_severity_chart,
    build_dayofweek_chart,
    build_hourly_chart,
    build_monthly_count_chart,
)

# 기본 데이터셋 디렉토리 설정값
from src.config import PROCESSED_DATASET_DIR

def _detect_years_from_files(dataset_path) -> List[int]:
    """
    데이터셋 경로에 있는 파일 이름에서 연도를 추출하는 헬퍼 함수.

    - 파일명 패턴: cve_cwe_dataset_YYYY.json
    - 예: cve_cwe_dataset_2020.json → 2020
    """
    years: List[int] = []
    pattern = re.compile(r"cve_cwe_dataset_(\d{4})\.json")
    # iter_dataset_files: 디렉토리 내 데이터셋 파일들을 순회하는 제너레이터
    for file in iter_dataset_files(dataset_path):
        match = pattern.search(file.name)
        if match:
            years.append(int(match.group(1)))
    return sorted(years)


@st.cache_data(show_spinner=False)
def _load_dataframe(dataset_path: Optional[str], years: Optional[Sequence[int]]) -> pd.DataFrame:
    """
    전처리된 DataFrame을 로드하고, Streamlit 캐시를 적용하는 함수.

    - dataset_path: 파일 또는 디렉토리 경로 (None이면 기본값 사용)
    - years: 로드할 연도 리스트 (None이면 전체)
    """
    # load_processed_dataframe 내부에서 Path 처리 등 수행
    return load_processed_dataframe(dataset_path or None, years=years)


def run_app(dataset_path: Optional[str] = None) -> None:
    """
    Streamlit 앱 메인 엔트리 함수.
    화면 구성과 사용자 인터랙션을 모두 여기서 처리.
    """
    # 페이지 기본 설정 (제목, 레이아웃)
    st.set_page_config(page_title="CVE/CWE CVSS Explorer", layout="wide")
    st.title("CVE/CWE CVSS Explorer")

    # 사이드바: 데이터셋 경로 입력
    default_path = dataset_path or str(PROCESSED_DATASET_DIR)
    path_input = st.sidebar.text_input("Dataset path (file or dir)", value=default_path)

    # 사용 가능한 연도 목록을 파일명에서 자동 감지
    available_years = _detect_years_from_files(path_input)
    # 사이드바: 로드할 연도 선택 (멀티 선택)
    selected_years = st.sidebar.multiselect(
        "Years to load",
        options=available_years,
        default=available_years,
    )

    # 데이터 로딩 영역
    with st.spinner("Loading dataset..."):
        # 연도 필터가 비어 있으면 None → 전체 연도 로드
        df = _load_dataframe(path_input, years=selected_years or None)
    st.success(f"Loaded {len(df):,} records")  # 로드된 레코드 수 표시

    # --------------------------------
    # 1) 시간 기반 차트
    # --------------------------------
    st.subheader("Time-based counts")
    # 시간 기준 선택 (연-월, 요일, 시간대)
    time_col = st.selectbox(
        "Time column",
        options=["year_month", "day_name", "hour"],
        index=0,
    )
    try:
        if time_col == "year_month":
            time_fig = build_monthly_count_chart(df)
        elif time_col == "day_name":
            time_fig = build_dayofweek_chart(df)
        else:
            time_fig = build_hourly_chart(df)
        st.plotly_chart(time_fig, use_container_width=True)
    except Exception as exc:
        # 오류 발생 시 사용자에게 경고 메시지
        st.warning(f"Time chart unavailable: {exc}")

    # --------------------------------
    # 2) CVSS severity 분포
    # --------------------------------
    st.subheader("CVSS severity distribution")
    metric_options = {
        "CVSS v3.1": "metrics.cvssMetricV31",
        "CVSS v2": "metrics.cvssMetricV2",
    }
    metric_label = st.radio("CVSS version", options=list(metric_options.keys()), index=0, horizontal=True)
    metric_col = metric_options[metric_label]
    try:
        # 선택된 버전에 대한 severity 분포 그래프 생성
        severity_fig = build_cvss_severity_chart(df, metric_col=metric_col)
        st.plotly_chart(severity_fig, use_container_width=True)
    except Exception as exc:
        st.warning(f"Severity chart unavailable: {exc}")

    # --------------------------------
    # 3) CVSS baseScore 구간(bin) 히스토그램
    # --------------------------------
    st.subheader("CVSS baseScore bins")
    # 점수 구간을 문자열로 입력받음 (예: "0,3,6,8,10")
    bins_input = st.text_input("Score bins (comma-separated)", value="0,3,6,8,10")
    try:
        # 입력 문자열을 , 기준으로 나눠 float 리스트로 변환
        bins = [float(x.strip()) for x in bins_input.split(",") if x.strip()]
        if len(bins) < 2:
            raise ValueError("Bins must include at least two edges")
        # 해당 구간으로 점수 binning 후 분포 그래프 생성
        score_fig = build_cvss_score_bin_chart(df, metric_col=metric_col, bins=bins)
        st.plotly_chart(score_fig, use_container_width=True)
    except Exception as exc:
        st.warning(f"Score histogram unavailable: {exc}")

    # --------------------------------
    # 4) CWE 빈도 상위 N개
    # --------------------------------
    st.subheader("Top CWE categories")
    # 상위 몇 개까지 볼지 슬라이더로 선택
    top_n = st.slider("Top N", min_value=5, max_value=50, value=20, step=5)
    try:
        # cwes 컬럼을 explode해서 상위 CWE 빈도 그래프 생성
        cwe_fig = build_cwe_top_chart(df, top_n=top_n)
        st.plotly_chart(cwe_fig, use_container_width=True)
    except Exception as exc:
        st.warning(f"CWE chart unavailable: {exc}")


# 모듈을 스크립트로 직접 실행했을 때만 앱을 실행
if __name__ == "__main__":
    run_app()
