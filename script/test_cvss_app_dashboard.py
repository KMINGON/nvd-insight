from __future__ import annotations

"""Streamlit test dashboard for CVSS visualizations.
CVSS 관련 시각화를 실험/검증하기 위한 Streamlit 대시보드 스크립트입니다.
"""

import re
import sys
from pathlib import Path
from typing import List, Optional, Sequence

import streamlit as st

# ---------------------------------------------------------------------------
# 프로젝트 루트를 sys.path에 추가
# - `streamlit run script/test_cvss_app_dashboard.py` 로 실행할 때
#   현재 작업 디렉토리가 바뀌면서 src 패키지를 못 찾는 문제를 방지하기 위함.
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 전처리된 데이터셋 로더 및 파일 이터레이터
from src.analytics.base_loader import iter_dataset_files, load_processed_dataframe  # noqa: E402

# CVSS 전용 차트/요약 함수들
from src.analytics.charts.cvss_app import (  # noqa: E402
    build_cvss_score_bin_chart,      # baseScore 구간(bin) 분포 차트 생성
    build_cvss_severity_chart,       # baseSeverity 분포 차트 생성
    summarize_cvss_availability,     # CVSS 데이터 존재 여부 요약 테이블 생성
)

# 설정에서 가져오는 전처리 데이터셋 기본 디렉토리
from src.config import PROCESSED_DATASET_DIR  # noqa: E402


# ---------------------------------------------------------------------------
# 1. 데이터셋 파일명에서 연도 자동 추론
# ---------------------------------------------------------------------------
def _detect_years(dataset_path: str | None) -> List[int]:
    """Infer available years from processed dataset filenames.

    - 입력: 데이터셋 경로(디렉토리 기준)
    - 동작: 디렉토리 내부의 파일명 중
      'cve_cwe_dataset_YYYY.json' 패턴과 매칭되는 연도(YYYY)를 추출해 리스트로 반환
    """
    if not dataset_path:
        # 경로가 비어 있으면 연도 정보를 알 수 없으므로 빈 리스트 반환
        return []
    years: list[int] = []
    # 파일명 패턴: 예) cve_cwe_dataset_2020.json
    pattern = re.compile(r"cve_cwe_dataset_(\d{4})\.json")
    try:
        # iter_dataset_files: 주어진 경로에서 데이터셋 파일들을 순회하는 헬퍼 함수
        for file in iter_dataset_files(dataset_path):
            match = pattern.search(file.name)
            if match:
                years.append(int(match.group(1)))  # 정규식 그룹에서 연도 부분만 추출해 int로 변환
    except FileNotFoundError:
        # 디렉토리가 없거나 접근 불가한 경우
        return []
    # 중복 제거(set) 후 정렬해서 반환
    return sorted(set(years))


# ---------------------------------------------------------------------------
# 2. DataFrame 로더 (Streamlit 캐시 적용)
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def _load_dataframe(path_input: str, years: Optional[Sequence[int]]) -> "pd.DataFrame":
    """
    주어진 경로(path_input)에 따라 전처리된 DataFrame을 로드하는 함수.

    - path_input이 파일이면: 그 파일만 로드 (years 무시)
    - path_input이 디렉토리면: 선택된 years 목록에 따라 여러 연도 파일을 로드
    - Streamlit의 cache_data를 사용해 동일 인자 호출 시 재사용
    """
    import pandas as pd  # type: ignore  # 함수 내부에서 import하여 초기 로딩 최소화

    path = Path(path_input)

    if path.is_file():
        # 단일 파일 입력 시에는 연도 필터를 무시하고 해당 파일만 사용
        years = None
        return load_processed_dataframe(dataset_path=path)

    # 디렉토리 입력 시: 선택된 연도(years)에 해당하는 파일들을 합쳐서 로드
    return load_processed_dataframe(years=years or None, dataset_dir=path)


# ---------------------------------------------------------------------------
# 3. Streamlit 메인 대시보드
# ---------------------------------------------------------------------------
def main() -> None:
    """CVSS 관련 차트들을 테스트하기 위한 Streamlit 대시보드 진입점."""
    # 페이지 메타 정보 및 레이아웃 설정
    st.set_page_config(page_title="CVSS Charts Test Dashboard", layout="wide")
    st.title("CVSS Charts Test Dashboard")

    # ----------------------------
    # 사이드바: 데이터셋 경로 입력
    # ----------------------------
    default_path = str(PROCESSED_DATASET_DIR)
    path_input = st.sidebar.text_input("Dataset path (file or dir)", value=default_path)

    # 디렉토리라면 파일명에서 사용 가능한 연도들을 자동으로 추론
    available_years = _detect_years(path_input)

    # 로드할 연도 선택 (단일 파일일 경우에는 기능적으로 무시됨)
    selected_years = st.sidebar.multiselect(
        "Years to load (directory only)",
        options=available_years,
        default=available_years,
    )

    # ----------------------------
    # 데이터 로딩
    # ----------------------------
    try:
        with st.spinner("Loading dataset..."):
            # selected_years가 비어 있으면 None을 넘겨서 전체 연도를 로드
            df = _load_dataframe(path_input, years=selected_years or None)
        st.success(f"Loaded {len(df):,} records")
    except FileNotFoundError as exc:
        # 경로가 잘못되었거나 파일이 없는 경우 사용자에게 에러 표시 후 종료
        st.error(f"데이터셋을 찾을 수 없습니다: {exc}")
        st.stop()

    # ----------------------------
    # CVSS 버전 선택 옵션 (v3.1 / v2)
    # ----------------------------
    metric_options = {
        "CVSS v3.1": "metrics.cvssMetricV31",
        "CVSS v2": "metrics.cvssMetricV2",
    }

    # ----------------------------
    # 탭 구성: Availability / Severity / Score bins
    # ----------------------------
    tabs = st.tabs(["Availability", "Severity", "Score bins"])

    # -----------------------------------------------------------------------
    # 탭 0: CVSS 데이터 존재 여부 요약
    # -----------------------------------------------------------------------
    with tabs[0]:
        st.subheader("CVSS 데이터 존재 여부 요약")
        # v3.1 / v2 컬럼이 얼마나 채워져 있는지 요약한 테이블 생성
        summary_df = summarize_cvss_availability(df)
        st.dataframe(summary_df)

    # -----------------------------------------------------------------------
    # 탭 1: Base Severity 분포
    # -----------------------------------------------------------------------
    with tabs[1]:
        st.subheader("Base Severity 분포")

        # 어떤 CVSS 버전(v3.1 / v2)을 기준으로 할지 선택
        metric_label = st.radio(
            "CVSS version",
            options=list(metric_options.keys()),
            index=0,             # 기본값: CVSS v3.1
            horizontal=True,     # 가로 방향 배치
            key="severity_metric",
        )
        metric_col = metric_options[metric_label]

        try:
            # 선택한 버전의 baseSeverity 분포 차트 생성
            fig_severity = build_cvss_severity_chart(df, metric_col=metric_col)
            st.plotly_chart(fig_severity, use_container_width=True)
        except Exception as exc:
            # 데이터 부족/컬럼 없음 등의 문제 발생 시 경고 메시지 출력
            st.warning(f"Severity chart unavailable: {exc}")

    # -----------------------------------------------------------------------
    # 탭 2: Base Score 구간(bin) 분포
    # -----------------------------------------------------------------------
    with tabs[2]:
        st.subheader("Base Score 구간 분포")

        # Score bins 탭에서도 CVSS 버전 선택 (독립적인 위젯이므로 key를 다르게 지정)
        metric_label = st.radio(
            "CVSS version",
            options=list(metric_options.keys()),
            index=0,
            horizontal=True,
            key="score_metric",
        )
        metric_col = metric_options[metric_label]

        # 점수 구간을 콤마로 입력받는 텍스트 인풋
        bins_input = st.text_input("Score bins (comma-separated)", value="0,3,6,8,10")

        try:
            # 입력 문자열을 ',' 기준으로 자르고 float로 변환
            bins = [float(x.strip()) for x in bins_input.split(",") if x.strip()]
            if len(bins) < 2:
                # 구간 경계가 최소 2개 이상이 아니면 올바른 bin이 아니므로 에러
                raise ValueError("Bins must include at least two edges.")

            # baseScore를 지정한 구간으로 나눈 히스토그램/막대 차트 생성
            fig_bins = build_cvss_score_bin_chart(df, metric_col=metric_col, bins=bins)
            st.plotly_chart(fig_bins, use_container_width=True)
        except Exception as exc:
            st.warning(f"Score histogram unavailable: {exc}")


# ---------------------------------------------------------------------------
# 스크립트로 직접 실행될 때만 main() 호출
# - 다른 모듈에서 import할 경우 자동 실행되지 않도록 하기 위함
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
