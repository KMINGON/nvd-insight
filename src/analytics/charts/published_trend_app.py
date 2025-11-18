from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

import pandas as pd
import plotly.express as px
from plotly.graph_objects import Figure


DEFAULT_DATE_COLUMN = "published"


@dataclass
class PublishedSummary:
    """Lightweight structure describing the extracted datetime series."""

    series: pd.Series
    date_column: str = DEFAULT_DATE_COLUMN

    @classmethod
    def from_dataframe(cls, df: pd.DataFrame, *, date_column: str = DEFAULT_DATE_COLUMN) -> "PublishedSummary":
        """
        Convert the provided datetime column into a normalized pandas Series.

        Drops rows where the conversion fails to avoid NaT entries during grouping.
        """
        if date_column not in df.columns:
            raise ValueError(f"'{date_column}' column missing from dataframe")
        series = pd.to_datetime(df[date_column], errors="coerce").dropna()
        return cls(series=series, date_column=date_column)


def summarize_yearly_counts(df: pd.DataFrame, *, date_column: str = DEFAULT_DATE_COLUMN) -> pd.DataFrame:
    """
    Aggregate CVE counts per year based on the published column.
    """
    summary = PublishedSummary.from_dataframe(df, date_column=date_column)
    counts = (
        summary.series.dt.year.value_counts()
        .sort_index()
        .rename_axis("year")
        .reset_index(name="count")
    )
    return counts


def summarize_monthly_counts(
    df: pd.DataFrame,
    *,
    date_column: str = DEFAULT_DATE_COLUMN,
    year: Optional[int] = None,
) -> pd.DataFrame:
    """
    Aggregate CVE counts per month. When `year` is provided, the DataFrame
    is filtered to that specific year before aggregation.
    """
    summary = PublishedSummary.from_dataframe(df, date_column=date_column)
    series = summary.series
    if year is not None:
        series = series[series.dt.year == year]
    month_index = series.dt.to_period("M").dt.to_timestamp()
    counts = (
        month_index.value_counts()
        .sort_index()
        .rename_axis("month")
        .reset_index(name="count")
    )
    return counts


def build_yearly_published_trend(
    df: pd.DataFrame,
    *,
    date_column: str = DEFAULT_DATE_COLUMN,
    title: str = "CVE Published Count by Year",
) -> Figure:
    """
    Build a bar chart visualizing yearly CVE publication volume.
    """
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


def build_monthly_published_trend(
    df: pd.DataFrame,
    *,
    date_column: str = DEFAULT_DATE_COLUMN,
    focus_year: Optional[int] = None,
    title: Optional[str] = None,
) -> Figure:
    """
    Build a line chart that highlights CVE publication cadence by month.

    Args:
        df: Normalized DataFrame from `load_processed_dataframe`.
        date_column: Column name containing ISO datetime strings.
        focus_year: Optional year for filtering. When omitted, all records
            are included which is useful for spotting multi-year seasonality.
        title: Optional override for the figure title.
    """
    summary = summarize_monthly_counts(df, date_column=date_column, year=focus_year)
    pretty_title = title or (
        f"CVE Monthly Trend ({focus_year})" if focus_year else "CVE Monthly Trend (All Years)"
    )
    fig = px.line(
        summary,
        x="month",
        y="count",
        markers=True,
        title=pretty_title,
        labels={"month": "Month", "count": "CVE Count"},
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40), hovermode="x unified")
    return fig


def build_publication_heatmap(
    df: pd.DataFrame,
    *,
    date_column: str = DEFAULT_DATE_COLUMN,
    title: str = "CVE Publication Heatmap (Year vs Month)",
) -> Figure:
    """
    Build a heatmap displaying the distribution of CVE publications by year/month.

    The heatmap is useful for spotting seasonal peaks or outliers that a simple
    line chart might obscure.
    """
    summary = PublishedSummary.from_dataframe(df, date_column=date_column)
    frame = pd.DataFrame(
        {
            "year": summary.series.dt.year,
            "month": summary.series.dt.month,
        }
    )
    pivot = (
        frame.groupby(["year", "month"])
        .size()
        .rename("count")
        .reset_index()
        .pivot(index="month", columns="year", values="count")
        .fillna(0)
        .sort_index()
    )
    fig = px.imshow(
        pivot,
        aspect="auto",
        labels=dict(x="Year", y="Month", color="CVE Count"),
        title=title,
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))
    return fig


def _describe_dataframe(df: pd.DataFrame, *, date_column: str = DEFAULT_DATE_COLUMN) -> str:
    """
    Helper for quick CLI debugging or __main__ usage.
    """
    summary = PublishedSummary.from_dataframe(df, date_column=date_column)
    return (
        f"records={len(df):,}, valid_dates={len(summary.series):,}, "
        f"min_date={summary.series.min()}, max_date={summary.series.max()}"
    )


# TODO: add support for vendor or CWE filters to narrow charts for specific slices.
# TODO: consider returning supplementary aggregated DataFrames to share with other consumers.


__all__ = [
    "build_monthly_published_trend",
    "build_publication_heatmap",
    "build_yearly_published_trend",
    "summarize_monthly_counts",
    "summarize_yearly_counts",
]


if __name__ == "__main__":  # pragma: no cover - convenience check
    try:
        import pandas as pd  # noqa: WPS433  # local import for quick smoke test

        sample = pd.DataFrame({"published": ["2024-01-01T00:00:00Z", "2024-02-01T00:00:00Z"]})
        print(_describe_dataframe(sample))
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"Unable to summarize sample dataframe: {exc}") from exc
