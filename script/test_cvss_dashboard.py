from __future__ import annotations  # 향후 타입 힌트 기능 사용(| 문법 등)을 위해 추가

import re  # 정규 표현식 사용 모듈
import sys  # 파이썬 경로(sys.path) 조작, 실행 환경 제어용
from pathlib import Path  # 파일/디렉토리 경로를 객체로 다루기 위한 모듈
from typing import List, Optional, Sequence  # 타입 힌트용 타입들

import pandas as pd  # 데이터 분석/처리를 위한 pandas
import streamlit as st  # 웹 대시보드 앱을 위한 Streamlit


# ---------------------------------------------------------------------------
# 1. 프로젝트 루트 경로를 sys.path에 추가
#    - 패키지 설치 없이도 src 패키지를 import할 수 있게 하기 위함
# ---------------------------------------------------------------------------
# 현재 파일 경로 기준으로 상위 1단계 폴더를 프로젝트 루트로 간주
PROJECT_ROOT = Path(__file__).resolve().parents[1]
# sys.path에 프로젝트 루트 경로가 없다면 추가
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 이제 src 패키지 내부 모듈들을 import할 수 있음
from src.analytics.base_loader import iter_dataset_files, load_processed_dataframe
from src.analytics.charts import (  # noqa: E402  # (E402: import 위치 관련 린트 경고 무시)
    build_cwe_top_chart,           # CWE Top-N 차트 함수
    build_cvss_score_bin_chart,    # CVSS 점수 구간(bin) 차트 함수
    build_cvss_severity_chart,     # CVSS severity 분포 차트 함수
    build_dayofweek_chart,         # 요일별 카운트 차트 함수
    build_hourly_chart,            # 시간대별 카운트 차트 함수
    build_monthly_count_chart,     # 월별 카운트 차트 함수
    summarize_cvss_availability,   # CVSS 데이터 존재 여부 요약 함수
)
from src.config import PROCESSED_DATASET_DIR  # noqa: E402  # 전처리 데이터셋 기본 디렉토리 설정값


# ---------------------------------------------------------------------------
# 2. 데이터셋 파일 이름에서 연도 검출
#    - cve_cwe_dataset_YYYY.json 형태 파일명에서 YYYY를 추출
# ---------------------------------------------------------------------------
def _detect_years(dataset_path: str | Path) -> List[int]:
    """파일명 패턴에서 연도를 추출한다."""
    years: List[int] = []  # 연도들을 담을 리스트
    pattern = re.compile(r"cve_cwe_dataset_(\d{4})\.json")  # 파일명 패턴 정의 (YYYY 캡처)
    # iter_dataset_files: 주어진 경로 아래의 데이터셋 파일들을 순회하는 제너레이터
    for file in iter_dataset_files(dataset_path):
        match = pattern.search(file.name)  # 파일 이름에서 패턴 검색
        if match:
            years.append(int(match.group(1)))  # 매칭된 연도 문자열을 int로 변환해서 리스트에 추가
    return sorted(set(years))  # 중복 제거(set) 후 오름차순 정렬하여 반환


# ---------------------------------------------------------------------------
# 3. 전처리된 DataFrame 로딩 + Streamlit 캐시
#    - 동일한 입력(dataset_path, years)로 여러 번 호출해도 한 번만 로딩되도록 캐싱
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=False)  # 데이터 캐시: 같은 인자 호출 시 결과 재사용, 스피너는 따로 안 보이게
def _load_df(dataset_path: Optional[str], years: Optional[Sequence[int]]) -> pd.DataFrame:
    """
    전처리된 DataFrame을 로드하는 헬퍼 함수.
    - dataset_path가 None이면 기본 동작(load_processed_dataframe 내부에서 처리)
    - years는 로드할 연도 리스트 (None이면 전체)
    """
    return load_processed_dataframe(dataset_path or None, years=years)


# ---------------------------------------------------------------------------
# 4. Streamlit 메인 앱 함수
#    - 페이지 설정, 사이드바 입력, 탭 UI, 각 탭에 차트/테이블 렌더링
# ---------------------------------------------------------------------------
def main() -> None:
    """
    전체 Streamlit 대시보드를 구성하는 메인 함수.
    """
    # 페이지 메타 정보 및 레이아웃 설정
    st.set_page_config(page_title="CVSS Charts Test Dashboard", layout="wide")
    # 상단 타이틀
    st.title("CVSS Charts Test Dashboard")

    # --- 사이드바: 데이터셋 경로 및 연도 선택 ---
    default_path = str(PROCESSED_DATASET_DIR)  # 기본 데이터셋 경로(설정값)
    # 사용자에게 데이터셋 경로를 입력받는 텍스트 박스 (사이드바)
    dataset_path = st.sidebar.text_input("Dataset path (file or dir)", value=default_path)

    # 입력된 경로 아래에서 사용 가능한 연도 목록을 파일명으로부터 자동 감지
    available_years = _detect_years(dataset_path) or []  # 감지된 연도가 없으면 빈 리스트
    # 로드할 연도 선택 (멀티 셀렉트)
    selected_years = st.sidebar.multiselect(
        "Years",              # 위젯 라벨
        options=available_years,  # 선택지: 감지된 연도들
        default=available_years,  # 기본: 전체 연도 선택
    )

    # --- 데이터 로딩 영역 ---
    with st.spinner("Loading dataset..."):  # 로딩 중 스피너 표시
        # 선택된 연도가 비어 있으면 None을 넘겨 전체 데이터를 로드
        df = _load_df(dataset_path, years=selected_years or None)
    # 로딩 완료 메시지 + 레코드 수 표시
    st.success(f"Loaded {len(df):,} records")

    # --- 탭 구성: 각 탭마다 하나의 분석/시각화 ---
    tabs = st.tabs(
        [
            "Month",             # 0: 월별 카운트
            "Weekday",           # 1: 요일별 카운트
            "Hour",              # 2: 시간대별 카운트
            "CVSS Severity",     # 3: CVSS severity 분포
            "CVSS Score Bins",   # 4: CVSS 점수 구간 분포
            "Top CWE",           # 5: CWE Top-N
            "CVSS Availability", # 6: CVSS 데이터 존재 여부 요약
        ]
    )

    # -----------------------------------------------------------------------
    # 탭 0: 월별 카운트
    # -----------------------------------------------------------------------
    with tabs[0]:
        st.subheader("Count by Month")  # 섹션 소제목
        try:
            fig = build_monthly_count_chart(df)  # 월별 카운트용 Plotly Figure 생성
            st.plotly_chart(fig, use_container_width=True)  # 그래프 렌더링
        except Exception as exc:
            # 그래프 생성 중 예외 발생 시 경고 메시지 출력
            st.warning(f"Month chart unavailable: {exc}")

    # -----------------------------------------------------------------------
    # 탭 1: 요일별 카운트
    # -----------------------------------------------------------------------
    with tabs[1]:
        st.subheader("Count by Weekday")  # 섹션 소제목
        try:
            fig = build_dayofweek_chart(df)  # 요일별 카운트용 Figure 생성
            st.plotly_chart(fig, use_container_width=True)
        except Exception as exc:
            st.warning(f"Weekday chart unavailable: {exc}")

    # -----------------------------------------------------------------------
    # 탭 2: 시간대(hour 버킷)별 카운트
    # -----------------------------------------------------------------------
    with tabs[2]:
        st.subheader("Count by Hour Bucket")  # 섹션 소제목
        try:
            fig = build_hourly_chart(df)  # 시간대별(또는 구간별) 카운트용 Figure 생성
            st.plotly_chart(fig, use_container_width=True)
        except Exception as exc:
            st.warning(f"Hour chart unavailable: {exc}")

    # -----------------------------------------------------------------------
    # 탭 3: CVSS Severity 분포
    #   - metrics.cvssMetricV31 또는 metrics.cvssMetricV2 컬럼을 기준으로
    # -----------------------------------------------------------------------
    with tabs[3]:
        st.subheader("CVSS Severity Distribution")  # 섹션 소제목
        # 어떤 CVSS 메트릭 컬럼을 사용할지 선택 (v3.1 또는 v2)
        metric_col = st.selectbox(
            "Metric column",                             # 라벨
            options=["metrics.cvssMetricV31", "metrics.cvssMetricV2"],  # 선택 가능한 컬럼
            index=0,                                     # 기본값: v3.1
        )
        try:
            fig = build_cvss_severity_chart(df, metric_col=metric_col)  # 선택된 컬럼 기준으로 severity 차트 생성
            st.plotly_chart(fig, use_container_width=True)
        except Exception as exc:
            st.warning(f"Severity chart unavailable: {exc}")

    # -----------------------------------------------------------------------
    # 탭 4: CVSS 점수 구간(bin) 분포
    #   - 사용자 입력 bins로 baseScore를 구간 나눠 분포 그리기
    # -----------------------------------------------------------------------
    with tabs[4]:
        st.subheader("CVSS baseScore Bins")  # 섹션 소제목
        # 점수 구간에 사용할 CVSS 메트릭 컬럼 선택 (v3.1 또는 v2)
        metric_col = st.selectbox(
            "Metric column for bins",                    # 라벨
            options=["metrics.cvssMetricV31", "metrics.cvssMetricV2"],  # 선택지
            index=0,                                     # 기본값: v3.1
            key="metric_bins",                           # Streamlit 위젯 키 (다른 selectbox와 구분)
        )
        # 사용자가 직접 점수 구간(bins)을 입력
        bins_input = st.text_input("Bins (comma-separated)", value="0,3,6,8,10")
        try:
            # 입력 문자열을 ','로 나누고 공백 제거 후 float로 형변환
            bins = [float(item.strip()) for item in bins_input.split(",") if item.strip()]
            if len(bins) < 2:
                # 구간 경계가 2개 미만이면 구간이 형성되지 않으므로 예외 처리
                raise ValueError("Provide at least two bin edges.")
            # 지정한 bins로 baseScore를 구간 나눠 분포 그래프 생성
            fig = build_cvss_score_bin_chart(df, metric_col=metric_col, bins=bins)
            st.plotly_chart(fig, use_container_width=True)
        except Exception as exc:
            st.warning(f"Score bin chart unavailable: {exc}")

    # -----------------------------------------------------------------------
    # 탭 5: CWE Top-N 빈도
    # -----------------------------------------------------------------------
    with tabs[5]:
        st.subheader("Top CWE Categories")  # 섹션 소제목
        # 상위 몇 개까지 볼지 슬라이더로 선택 (5~50, 5 단위)
        top_n = st.slider("Top N", min_value=5, max_value=50, value=20, step=5)
        try:
            # 상위 top_n개의 CWE ID 빈도 차트 생성
            fig = build_cwe_top_chart(df, top_n=top_n)
            st.plotly_chart(fig, use_container_width=True)
        except Exception as exc:
            st.warning(f"CWE chart unavailable: {exc}")

    # -----------------------------------------------------------------------
    # 탭 6: CVSS 데이터 존재 여부 요약
    #   - metrics.cvssMetricV31 / metrics.cvssMetricV2 컬럼 존재 여부
    #   - baseScore / baseSeverity가 얼마나 채워져 있는지 요약 테이블
    # -----------------------------------------------------------------------
    with tabs[6]:
        st.subheader("CVSS Availability Summary")  # 섹션 소제목
        try:
            summary_df = summarize_cvss_availability(df)  # CVSS 데이터 존재 여부 요약 DataFrame 생성
            st.dataframe(summary_df, use_container_width=True)  # 테이블 렌더링
        except Exception as exc:
            st.warning(f"Availability summary unavailable: {exc}")


# ---------------------------------------------------------------------------
# 5. 스크립트 직접 실행 진입점
#    - 모듈로 import될 때는 실행되지 않고, `python this_file.py` 일 때만 실행
# ---------------------------------------------------------------------------
if __name__ == "__main__":  # 이 파일이 직접 실행될 때만
    main()  # 메인 Streamlit 앱 실행
