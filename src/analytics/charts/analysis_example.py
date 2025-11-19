from __future__ import annotations

from pathlib import Path
from typing import Optional

import pandas as pd
import plotly.express as px
from plotly.graph_objects import Figure


def summarize_counts_by_year(df: pd.DataFrame, date_column: str = "published") -> pd.DataFrame:
    """
    Convert CVE 데이터의 날짜 컬럼을 연도 단위로 집계해 DataFrame으로 반환한다.

    Args:
        df: `load_processed_dataframe`로 불러온 pandas DataFrame.
        date_column: 연도 카운트를 계산할 datetime 문자열 컬럼명.
    """
    if date_column not in df.columns:
        raise ValueError(f"{date_column} column missing from dataframe")
    years = (
        pd.to_datetime(df[date_column], errors="coerce")
        .dropna()
        .dt.year
    )
    summary = (
        years.value_counts()
        .sort_index()
        .rename_axis("year")
        .reset_index(name="count")
    )
    return summary


def build_yearly_cve_chart(
    df: pd.DataFrame,
    *,
    date_column: str = "published",
    title: str = "CVE Publication Trend",
) -> Figure:
    """
    예시 분석: 연도별 CVE 건수를 막대그래프로 표현한 Plotly Figure를 생성한다.
    """
    summary = summarize_counts_by_year(df, date_column=date_column)
    fig = px.bar(
        summary,
        x="year",
        y="count",
        labels={"year": "Year", "count": "CVE Count"},
        title=title,
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))
    return fig