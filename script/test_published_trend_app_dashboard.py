from __future__ import annotations

import re
from typing import List, Optional, Sequence

from pathlib import Path
import sys

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analytics.base_loader import iter_dataset_files, load_processed_dataframe
from src.analytics.charts import published_trend_app as trend_charts


def discover_available_years() -> List[int]:
    """
    Inspect processed dataset filenames and extract the four-digit year suffix.
    """
    year_pattern = re.compile(r"(\d{4})$")
    years: set[int] = set()
    for dataset_path in iter_dataset_files():
        match = year_pattern.search(dataset_path.stem)
        if match:
            years.add(int(match.group(1)))
    return sorted(years)


def load_dataset(years: Sequence[int]) -> pd.DataFrame:
    """
    Wrapper around `load_processed_dataframe` with helpful error handling.
    """
    if not years:
        raise ValueError("At least one year must be selected to load the dataset.")
    return load_processed_dataframe(years=years)


def render_figure(figure) -> None:
    """
    Convenience renderer supporting Plotly or Altair figures.
    """
    if hasattr(figure, "to_plotly_json"):
        st.plotly_chart(figure, use_container_width=True)
    elif hasattr(figure, "to_dict"):
        st.altair_chart(figure, use_container_width=True)
    else:
        st.write("지원되지 않는 차트 형식입니다.", figure)


def main() -> None:
    st.set_page_config(page_title="Published Trend Test Dashboard", layout="wide")
    st.title("Published Trend 모듈 테스트")

    with st.sidebar:
        st.header("데이터 필터")
        available_years = discover_available_years()
        if not available_years:
            st.error("처리된 데이터셋을 찾을 수 없습니다. build_dataset.py를 먼저 실행하세요.")
            st.stop()

        year_selection = st.multiselect(
            "연도 선택",
            options=available_years,
            default=available_years,
            help="분석에 포함할 연도를 선택하세요.",
        )
        focus_year_label = st.selectbox(
            "월별 차트 기준 연도",
            options=["전체 연도"] + [str(year) for year in available_years],
            index=0,
        )
        focus_year: Optional[int] = None if focus_year_label == "전체 연도" else int(focus_year_label)

    if not year_selection:
        st.warning("최소 한 개 이상의 연도를 선택해야 합니다.")
        st.stop()

    try:
        df = load_dataset(year_selection)
    except Exception as exc:  # noqa: BLE001
        st.error(f"데이터 로딩 실패: {exc}")
        st.stop()

    st.sidebar.success(f"{len(df):,} 건 로드 완료")
    st.metric("총 CVE 레코드", f"{len(df):,}")

    tabs = st.tabs(["연도별 추이", "월별 추이", "연도-월 Heatmap"])

    with tabs[0]:
        st.subheader("연도별 Published 추이")
        fig_yearly = trend_charts.build_yearly_published_trend(df)
        render_figure(fig_yearly)

    with tabs[1]:
        st.subheader("월별 Published 추이")
        fig_monthly = trend_charts.build_monthly_published_trend(df, focus_year=focus_year)
        render_figure(fig_monthly)

    with tabs[2]:
        st.subheader("연도-월 Heatmap")
        fig_heatmap = trend_charts.build_publication_heatmap(df)
        render_figure(fig_heatmap)


if __name__ == "__main__":
    main()
