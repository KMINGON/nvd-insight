from __future__ import annotations

import re
from typing import List, Optional, Sequence

from pathlib import Path
import sys

import pandas as pd
import streamlit as st

# -------------------------------------------------------------------
# 📌 프로젝트 루트 경로를 sys.path에 추가하여 내부 모듈 import 문제 해결
#    (Streamlit은 실행 위치가 바뀌기 때문에 상대경로 문제가 발생함)
# -------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 내부 데이터 로딩, 차트 모듈 import
from src.analytics.base_loader import iter_dataset_files, load_processed_dataframe
from src.analytics.charts import vendor_product_chart as vp_charts


# -------------------------------------------------------------------
# 📌 데이터셋 파일 이름에서 연도(YYYY)를 자동으로 추출하는 함수
#    예: processed-2023.pkl → 2023
# -------------------------------------------------------------------
def discover_available_years() -> List[int]:
    """
    처리된 dataset 파일명의 4자리 숫자(연도) 부분을 추출하여 리스트로 반환한다.
    """
    year_pattern = re.compile(r"(\d{4})$")
    years: set[int] = set()

    for dataset_path in iter_dataset_files():
        match = year_pattern.search(dataset_path.stem)
        if match:
            years.add(int(match.group(1)))

    return sorted(years)


# -------------------------------------------------------------------
# 📌 특정 연도의 processed 데이터셋을 로드하는 함수
# -------------------------------------------------------------------
def load_dataset(years: Sequence[int]) -> pd.DataFrame:
    """
    선택된 연도들에 대해 load_processed_dataframe()을 호출하여 병합된 DataFrame을 반환.
    """
    if not years:
        raise ValueError("At least one year must be selected.")
    return load_processed_dataframe(years=years)


# -------------------------------------------------------------------
# 📌 Plotly 또는 Altair 객체를 Streamlit에서 자동 렌더링
# -------------------------------------------------------------------
def render_figure(figure) -> None:
    """
    전달된 figure가 Plotly인지 Altair인지 자동으로 구분하여 렌더링한다.
    """
    if hasattr(figure, "to_plotly_json"):  # Plotly
        st.plotly_chart(figure, use_container_width=True)
    elif hasattr(figure, "to_dict"):  # Altair
        st.altair_chart(figure, use_container_width=True)
    else:
        st.write("지원되지 않는 차트 형식입니다.", figure)


# -------------------------------------------------------------------
# 📌 Streamlit 대시보드 메인 함수
# -------------------------------------------------------------------
def main() -> None:
    # 페이지 기본 설정
    st.set_page_config(page_title="Vendor/Product Chart Dashboard", layout="wide")
    st.title("Vendor / Product 취약점 분포 테스트 대시보드")

    # -------------------------------
    # 📌 Sidebar (필터 UI)
    # -------------------------------
    with st.sidebar:
        st.header("데이터 필터")

        # 사용 가능한 연도 자동 추출
        available_years = discover_available_years()

        if not available_years:
            st.error("처리된 데이터셋을 찾을 수 없습니다. build_dataset.py를 먼저 실행하세요.")
            st.stop()

        # 연도 다중 선택
        year_selection = st.multiselect(
            "연도 선택",
            options=available_years,
            default=available_years,
            help="분석에 포함할 연도를 선택하세요.",
        )

        # Top-N 개수 선택
        top_n = st.slider(
            "상위 표시 개수",
            min_value=5,
            max_value=40,
            value=15,
            step=5,
        )

    # 연도 선택하지 않으면 중단
    if not year_selection:
        st.warning("최소 한 개 이상의 연도를 선택해야 합니다.")
        st.stop()

    # -------------------------------
    # 📌 실제 데이터 로딩
    # -------------------------------
    try:
        df = load_dataset(year_selection)
    except Exception as exc:
        st.error(f"데이터 로딩 실패: {exc}")
        st.stop()

    st.sidebar.success(f"{len(df):,} 건 로드 완료")
    st.metric("총 CVE 레코드", f"{len(df):,}")

    # -------------------------------
    # 📌 탭(Tab) UI 구성
    # -------------------------------
    tabs = st.tabs(["Vendor Top-N", "Product Top-N"])

    # -------------------------------
    # 📌 Vendor Top-N 탭
    # -------------------------------
    with tabs[0]:
        st.subheader("Vendor 상위 분포")
        fig_vendor = vp_charts.build_vendor_bar_chart(df, top_n=top_n)
        render_figure(fig_vendor)

    # -------------------------------
    # 📌 Product Top-N 탭
    # -------------------------------
    with tabs[1]:
        st.subheader("Product 상위 분포")
        fig_product = vp_charts.build_product_bar_chart(df, top_n=top_n)
        render_figure(fig_product)


# -------------------------------------------------------------------
# 📌 Streamlit entrypoint
# -------------------------------------------------------------------
if __name__ == "__main__":
    main()
