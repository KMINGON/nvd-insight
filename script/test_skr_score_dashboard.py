from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analytics.base_loader import load_processed_dataframe
from src.analytics.charts.skr_score import (
    build_cwe_score_chart,
    build_product_score_chart,
    build_skr_score_added_df,
    build_top10_chart,
    build_vendor_score_chart,
    build_top10_dataset,
    summarize_cwe_scores,
    summarize_product_counts,
    summarize_vendor_counts,
)


YEAR_OPTIONS = list(range(2020, 2026))
MAX_TOP_RESULTS = 20
TABLE_COLUMNS = [
    "cveId",
    "baseSeverity",
    "baseScore",
    "exploitabilityScore",
    "cisaExploitAdd",
    "published",
    "description",
]


# 기능: 지정 연도의 전처리 DataFrame을 로드해 캐시한다.
# 매개변수: year(정수 연도 값).
# 반환: 선택 연도의 pandas DataFrame.
@st.cache_data(show_spinner=False)
def _load_year_dataframe(year: int) -> pd.DataFrame:
    return load_processed_dataframe(years=[year])


# 기능: 연도별 데이터에 skrScore를 추가해 캐시한다.
# 매개변수: year(정수 연도 값).
# 반환: skrScore 컬럼이 포함된 pandas DataFrame.
@st.cache_data(show_spinner=False)
def _load_year_skr_dataframe(year: int) -> pd.DataFrame:
    df = _load_year_dataframe(year)
    return build_skr_score_added_df(df)


# 기능: st.dataframe 열 폭 옵션을 자동으로 계산한다.
# 매개변수: df(열 길이 측정을 위한 DataFrame).
# 반환: column_config에 사용할 설정 딕셔너리.
def _col_width_config(df: pd.DataFrame) -> dict:
    config = {}
    for column in TABLE_COLUMNS:
        if column not in df:
            continue
        max_len = int(df[column].astype(str).str.len().max())
        if max_len <= 30:
            width = "small"
        elif max_len <= 60:
            width = "medium"
        else:
            width = "large"
        config[column] = st.column_config.Column(column, width=width)
    return config


# 기능: 선택 연도별 Top10 차트를 렌더링한다.
# 매개변수: selected_years(연도 리스트), top10_map(연도별 Top10 DF), yearly_df(연도별 원본 DF).
# 반환: 없음(Streamlit UI 출력).
def _render_top10_charts_tab(
    selected_years: list[int],
    top10_map: dict[int, pd.DataFrame],
    yearly_df: dict[int, pd.DataFrame],
) -> None:
    # 연도별 Top10 막대 차트를 렌더링한다.
    for year in selected_years:
        st.subheader(f"{year} Top 10")
        st.caption(f"{year} 데이터 건수: {len(yearly_df[year]):,}")
        fig = build_top10_chart(top10_map[year])
        st.plotly_chart(fig, use_container_width=True, key=f"top10_chart_{year}")


# 기능: 연도별 Top10 상세 테이블을 표시한다.
# 매개변수: selected_years(연도 리스트), top10_map(연도별 Top10 DF).
# 반환: 없음(Streamlit UI 출력).
def _render_top10_table_tab(selected_years: list[int], top10_map: dict[int, pd.DataFrame]) -> None:
    for year in selected_years:
        st.subheader(f"{year} Top 10 상세")
        st.dataframe(
            top10_map[year][TABLE_COLUMNS],
            use_container_width=True,
            hide_index=True,
            height=400,
            column_config=_col_width_config(top10_map[year]),
        )


# 기능: 연도별 Vendor 요약 차트를 출력한다.
# 매개변수: selected_years(연도 리스트), vendor_summary(연도별 vendor 요약 DF), top_n(표시 개수).
# 반환: 없음(Streamlit UI 출력).
def _render_vendor_tab(
    selected_years: list[int], vendor_summary: dict[int, pd.DataFrame], top_n: int
) -> None:
    # Vendor 상위 순위를 차트로 출력한다.
    for year in selected_years:
        st.subheader(f"{year} 상위 Vendor (Top {top_n})")
        fig_vendor = build_vendor_score_chart(vendor_summary[year].head(top_n), title=f"{year} 상위 Vendor")
        st.plotly_chart(fig_vendor, use_container_width=True, key=f"vendor_chart_{year}")


# 기능: 연도별 Product 요약 차트를 출력한다.
# 매개변수: selected_years(연도 리스트), product_summary(연도별 product 요약 DF), top_n(표시 개수).
# 반환: 없음(Streamlit UI 출력).
def _render_product_tab(
    selected_years: list[int], product_summary: dict[int, pd.DataFrame], top_n: int
) -> None:
    # Product 상위 순위를 차트로 출력한다.
    for year in selected_years:
        st.subheader(f"{year} 상위 Product (Top {top_n})")
        fig_product = build_product_score_chart(
            product_summary[year].head(top_n), title=f"{year} 상위 Product"
        )
        st.plotly_chart(fig_product, use_container_width=True, key=f"product_chart_{year}")


# 기능: 연도별 CWE 차트와 상세 테이블을 출력한다.
# 매개변수: selected_years(연도 리스트), cwe_summary(연도별 CWE 요약 DF), top_n(표시 개수).
# 반환: 없음(Streamlit UI 출력).
def _render_cwe_tab(
    selected_years: list[int], cwe_summary: dict[int, pd.DataFrame], top_n: int
) -> None:
    # CWE 상위 순위를 차트 및 상세 테이블로 출력한다.
    for year in selected_years:
        st.subheader(f"{year} 상위 CWE (Top {top_n})")
        fig_cwe = build_cwe_score_chart(cwe_summary[year].head(top_n), title=f"{year} 상위 CWE")
        st.plotly_chart(fig_cwe, use_container_width=True, key=f"cwe_chart_{year}")
        cwe_df = cwe_summary[year].head(top_n)[
            [
                "cweId",
                "count",
                "score",
                "cweDescription",
                "cweExtendedDescription",
                "cweBackgroundDetails",
            ]
        ]
        st.dataframe(
            cwe_df,
            use_container_width=True,
            hide_index=True,
            height=300,
        )


# 기능: Streamlit 대시보드 엔트리 포인트로 UI와 렌더링을 제어한다.
# 매개변수: 없음(직접 실행 시 호출).
# 반환: 없음(Streamlit 앱 실행).
def main() -> None:
    st.set_page_config(page_title="SkrScore Top Analyzer", layout="wide")
    st.title("SkrScore 기반 취약점 리포트")

    with st.sidebar:
        st.header("데이터 선택")
        selected_years = st.multiselect(
            "연도를 선택하세요",
            options=YEAR_OPTIONS,
            default=[YEAR_OPTIONS[-1]],
            help="복수 연도를 선택하면 결합된 데이터로 Top 10을 계산합니다.",
        )
        if not selected_years:
            st.warning("최소 1개 이상의 연도를 선택하세요.")
            st.stop()
        top_n = st.slider(
            "(Vendor/Product/CWE) Top-N",
            min_value=3,
            max_value=MAX_TOP_RESULTS,
            value=5,
            step=1,
            help="Vendor/Product/CWE 탭에서 표시할 상위 항목 개수를 조정합니다.",
        )

    tabs = st.tabs(["Top 10 차트", "Top 10 데이터", "Vendor 분석", "Product 분석", "CWE 분석"])
    with st.spinner("데이터를 불러오는 중입니다..."):
        yearly_processed = {year: _load_year_dataframe(year) for year in selected_years}
        yearly_skr = {year: _load_year_skr_dataframe(year) for year in selected_years}
        top10_map = {
            year: build_top10_dataset(source_df=yearly_skr[year]) for year in selected_years
        }
        vendor_summary_full = {
            year: summarize_vendor_counts(yearly_skr[year], top_n=MAX_TOP_RESULTS)
            for year in selected_years
        }
        product_summary_full = {
            year: summarize_product_counts(yearly_skr[year], top_n=MAX_TOP_RESULTS)
            for year in selected_years
        }
        cwe_summary_full = {
            year: summarize_cwe_scores(yearly_skr[year], top_n=MAX_TOP_RESULTS)
            for year in selected_years
        }

    with tabs[0]:
        _render_top10_charts_tab(selected_years, top10_map, yearly_processed)
    with tabs[1]:
        _render_top10_table_tab(selected_years, top10_map)
    with tabs[2]:
        _render_vendor_tab(selected_years, vendor_summary_full, top_n)
    with tabs[3]:
        _render_product_tab(selected_years, product_summary_full, top_n)
    with tabs[4]:
        _render_cwe_tab(selected_years, cwe_summary_full, top_n)


if __name__ == "__main__":
    main()
