from __future__ import annotations

"""
CWE 시각화를 테스트하기 위한 Streamlit 대시보드.

- 디렉토리 또는 단일 JSON 파일을 입력받아 데이터 로드
- CWE Top-N 차트 / 테이블을 UI로 표현
- 실험/개발용 대시보드 목적
"""

import re
import sys
from pathlib import Path
from typing import List, Optional, Sequence

import streamlit as st

# -------------------------------------------------------------------
# 프로젝트 루트를 sys.path에 추가
# Streamlit으로 실행 시 현재 working directory가 달라져 import 에러가 날 수 있음.
# 따라서 프로젝트 최상위 디렉토리를 강제로 import 경로에 추가한다.
# -------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 전처리된 데이터 로더 및 연도 탐색 함수
from src.analytics.base_loader import iter_dataset_files, load_processed_dataframe  # noqa: E402

# CWE 관련 시각화 함수들
from src.analytics.charts.cwe import build_cwe_top_chart, summarize_cwe_counts  # noqa: E402

# 프로젝트 기본 설정(데이터셋 저장 디렉토리)
from src.config import PROCESSED_DATASET_DIR  # noqa: E402


# -------------------------------------------------------------------
# 연도 탐지 함수
# -------------------------------------------------------------------
def _detect_years(dataset_path: str | None) -> List[int]:
    """
    데이터셋 파일명에서 포함된 연도를 자동으로 추출하는 함수.

    - 파일명 패턴: cve_cwe_dataset_YYYY.json
    - 디렉토리 입력 시 내부 파일들을 모두 검사하여 years 목록 생성
    - 단일 파일 입력 시 빈 리스트 반환
    """
    if not dataset_path:
        return []

    years: list[int] = []
    pattern = re.compile(r"cve_cwe_dataset_(\d{4})\.json")

    try:
        # 디렉토리 내부 파일들을 순회하며 연도 추출
        for file in iter_dataset_files(dataset_path):
            match = pattern.search(file.name)
            if match:
                years.append(int(match.group(1)))
    except FileNotFoundError:
        # 디렉토리 자체가 없을 경우
        return []

    return sorted(set(years))


# -------------------------------------------------------------------
# 데이터 로딩 함수 (Streamlit 캐싱 적용)
# -------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def _load_dataframe(path_input: str, years: Optional[Sequence[int]]) -> "pd.DataFrame":
    """
    데이터 파일 또는 데이터셋 디렉토리를 읽어 DataFrame 생성.

    - path_input이 파일이면 해당 파일만 로드
    - 디렉토리면 선택된 연도(years)에 맞게 여러 파일을 로드
    - Streamlit 캐시로 재로딩 방지
    """
    import pandas as pd  # streamlit 캐시 안에서 사용

    path = Path(path_input)

    # 파일 입력 시 → 연도 선택 무시하고 단일 파일 로드
    if path.is_file():
        years = None
        return load_processed_dataframe(dataset_path=path)

    # 디렉토리 입력 시 → 선택된 연도(years)에 맞게 파일 로드
    return load_processed_dataframe(years=years or None, dataset_dir=path)


# -------------------------------------------------------------------
# Streamlit 메인 UI
# -------------------------------------------------------------------
def main() -> None:
    """CWE 시각화 테스트 Streamlit 대시보드."""
    st.set_page_config(page_title="CWE Charts Test Dashboard", layout="wide")
    st.title("CWE Charts Test Dashboard")

    # ------------------------------
    # 사이드바: 데이터 경로 입력
    # ------------------------------
    default_path = str(PROCESSED_DATASET_DIR)
    path_input = st.sidebar.text_input("Dataset path (file or dir)", value=default_path)

    # 선택 가능한 연도 자동 탐지
    available_years = _detect_years(path_input)

    # 연도 선택 UI (단일 파일일 경우 자동적으로 무시됨)
    selected_years = st.sidebar.multiselect(
        "Years to load (directory only)",
        options=available_years,
        default=available_years,
    )

    # ------------------------------
    # 데이터 로딩
    # ------------------------------
    try:
        with st.spinner("Loading dataset..."):
            df = _load_dataframe(path_input, years=selected_years or None)
        st.success(f"Loaded {len(df):,} records")
    except FileNotFoundError as exc:
        st.error(f"데이터셋을 찾을 수 없습니다: {exc}")
        st.stop()

    # ------------------------------
    # 탭 구성 (Top-N 차트 / Table)
    # ------------------------------
    tabs = st.tabs(["Top-N Chart", "Table"])

    # ------------------------------
    # Top-N Chart 탭
    # ------------------------------
    with tabs[0]:
        st.subheader("CWE Top-N 분포")
        top_n = st.slider("Top N", min_value=5, max_value=50, value=20, step=5)

        try:
            fig_cwe = build_cwe_top_chart(df, top_n=top_n)
            st.plotly_chart(fig_cwe, use_container_width=True)
        except Exception as exc:
            st.warning(f"CWE chart unavailable: {exc}")

    # ------------------------------
    # Table 탭
    # ------------------------------
    with tabs[1]:
        st.subheader("CWE Top-N 테이블")
        top_n = st.slider("Top N (table)", min_value=5, max_value=50, value=20, step=5)

        try:
            summary_df = summarize_cwe_counts(df, top_n=top_n)
            st.dataframe(summary_df)
        except Exception as exc:
            st.warning(f"CWE summary unavailable: {exc}")


# -------------------------------------------------------------------
# 스크립트 직접 실행 시 main() 실행
# -------------------------------------------------------------------
if __name__ == "__main__":
    main()
