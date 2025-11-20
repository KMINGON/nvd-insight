from __future__ import annotations # 실행 시점에 불필요한 의존성/오류 줄여줌.

from dataclasses import dataclass # 데이터 홀더 클래스(@dataclass)
from typing import Optional 

import pandas as pd
import plotly.express as px # 고수준 plotly Pandas, DataFrame과 바로 연동
from plotly.graph_objects import Figure


# 기본 날짜 컬럼 이름
DEFAULT_DATE_COLUMN = "published"


# ---------------------------------------------------------
# 날짜(published) 시리즈를 정규화해서 보관하는 데이터 구조
# ---------------------------------------------------------
@dataclass
class PublishedSummary:
    """정규화된 published datetime 시리즈를 보관하는 구조."""

    series: pd.Series  # datetime 변환 완료된 Series
    date_column: str = DEFAULT_DATE_COLUMN

    @classmethod
    def from_dataframe(cls, df: pd.DataFrame, *, date_column: str = DEFAULT_DATE_COLUMN) -> "PublishedSummary":
        """
        DataFrame에서 date_column을 datetime으로 변환해 유효한 값만 남긴 후 PublishedSummary 생성.
        """
        if date_column not in df.columns:
            raise ValueError(f"'{date_column}' column missing from dataframe")

        # datetime 변환 후 NaT 제거
        series = pd.to_datetime(df[date_column], errors="coerce").dropna()
        return cls(series=series, date_column=date_column)


# ---------------------------------------------------------
# 연도별 CVE count 집계
# ---------------------------------------------------------
def summarize_yearly_counts(df: pd.DataFrame, *, date_column: str = DEFAULT_DATE_COLUMN) -> pd.DataFrame:
    """published 기준으로 연도별 CVE 개수를 count하여 DataFrame으로 반환."""
    summary = PublishedSummary.from_dataframe(df, date_column=date_column)

    counts = (
        summary.series.dt.year.value_counts()  # 연도별 개수
        .sort_index()                          # 연도 순 정렬
        .rename_axis("year")
        .reset_index(name="count")
    )
    return counts
    
# 연도별 cve count 집계 -> published 기준으로 연도별 cve 개수를 count하여 df로 반환
# from_datetime으로 연도만 추출 -> 이후 count로 개수 집계


# ---------------------------------------------------------
# 월별 CVE count 집계
# ---------------------------------------------------------
def summarize_monthly_counts(
    df: pd.DataFrame,
    *,
    date_column: str = DEFAULT_DATE_COLUMN,
    year: Optional[int] = None,
) -> pd.DataFrame:
    """
    월별 CVE count 집계.
    - year 값이 있으면 특정 연도에 대해서만 월별 집계.
    """
    summary = PublishedSummary.from_dataframe(df, date_column=date_column)
    series = summary.series

    # 특정 연도 필터링
    if year is not None:
        series = series[series.dt.year == year]

    # 월 단위 Period → timestamp 변환
    month_index = series.dt.to_period("M").dt.to_timestamp()

    counts = (
        month_index.value_counts()
        .sort_index()
        .rename_axis("month")
        .reset_index(name="count")
    )
    return counts


# ---------------------------------------------------------
# 연도별 CVE bar chart 생성
# ---------------------------------------------------------
def build_yearly_published_trend(
    df: pd.DataFrame,
    *,
    date_column: str = DEFAULT_DATE_COLUMN,
    title: str = "CVE Published Count by Year",
) -> Figure:
    """연도별 CVE count 막대그래프 생성."""
    summary = summarize_yearly_counts(df, date_column=date_column)

    fig = px.bar(
        summary,
        x="year",
        y="count",
        labels={"year": "Year", "count": "CVE Count"},
        title=title,
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))
    return fig


# ---------------------------------------------------------
# 월별 CVE line chart 생성
# ---------------------------------------------------------
def build_monthly_published_trend(
    df: pd.DataFrame,
    *,
    date_column: str = DEFAULT_DATE_COLUMN,
    focus_year: Optional[int] = None,
    title: Optional[str] = None,
) -> Figure:
    """
    월별 CVE count 선그래프 생성.
    - focus_year가 있으면 해당 연도만 분석.
    """
    summary = summarize_monthly_counts(df, date_column=date_column, year=focus_year)

    pretty_title = title or (
        f"CVE Monthly Trend ({focus_year})" if focus_year else "CVE Monthly Trend (All Years)"
    )

    fig = px.line(
        summary,
        x="month",
        y="count",
        markers=True,  # 점 표시
        title=pretty_title,
        labels={"month": "Month", "count": "CVE Count"},
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40), hovermode="x unified")
    return fig


# ---------------------------------------------------------
# 연도 × 월 Heatmap 생성
# ---------------------------------------------------------
def build_publication_heatmap(
    df: pd.DataFrame,
    *,
    date_column: str = DEFAULT_DATE_COLUMN,
    title: str = "CVE Publication Heatmap (Year vs Month)",
) -> Figure:
    """
    연도와 월에 따른 CVE 분포를 Heatmap으로 시각화.
    """
    summary = PublishedSummary.from_dataframe(df, date_column=date_column)

    # 연도/월 정보 추출
    frame = pd.DataFrame({
        "year": summary.series.dt.year,
        "month": summary.series.dt.month,
    })

    # Pivot table 형태로 변환 → Heatmap 기반 데이터 구조
    pivot = (
        frame.groupby(["year", "month"])
        .size()
        .rename("count")
        .reset_index()
        .pivot(index="month", columns="year", values="count")
        .fillna(0)      # 빈 값은 0
        .sort_index()   # 월 기준 정렬
    )

    fig = px.imshow(
        pivot,
        aspect="auto",
        labels=dict(x="Year", y="Month", color="CVE Count"),
        title=title,
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))
    return fig


# ---------------------------------------------------------
# CLI·테스트용 데이터 요약 함수
# ---------------------------------------------------------
def _describe_dataframe(df: pd.DataFrame, *, date_column: str = DEFAULT_DATE_COLUMN) -> str:
    """데이터 요약 문자열 생성 (레코드 수, 날짜 범위)."""
    summary = PublishedSummary.from_dataframe(df, date_column=date_column)
    return (
        f"records={len(df):,}, valid_dates={len(summary.series):,}, "
        f"min_date={summary.series.min()}, max_date={summary.series.max()}"
    )


# ---------------------------------------------------------
# 모듈 외부 노출 목록
# ---------------------------------------------------------
__all__ = [
    "build_monthly_published_trend",
    "build_publication_heatmap",
    "build_yearly_published_trend",
    "summarize_monthly_counts",
    "summarize_yearly_counts",
]


# ---------------------------------------------------------
# 단독 실행 시 테스트 코드
# ---------------------------------------------------------
if __name__ == "__main__":
    try:
        import pandas as pd
        sample = pd.DataFrame({"published": ["2024-01-01T00:00:00Z", "2024-02-01T00:00:00Z"]})
        print(_describe_dataframe(sample))
    except Exception as exc:
        raise SystemExit(f"Unable to summarize sample dataframe: {exc}") from exc
