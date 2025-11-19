from __future__ import annotations

import pandas as pd
import plotly.express as px
from plotly.graph_objects import Figure

from .cvss_app import (
    DEFAULT_SCORE_BINS,
    SEVERITY_ORDER,
    build_cvss_score_bin_chart,
    build_cvss_severity_chart,
    extract_cvss_metrics,
    summarize_cvss_availability,
)


def _normalize_datetimes(df: pd.DataFrame, date_column: str) -> pd.Series:
    """
    Parse the given date column into a clean pandas Series for grouping.
    """
    if date_column not in df.columns:
        raise ValueError(f"{date_column} column missing from dataframe")
    series = pd.to_datetime(df[date_column], errors="coerce").dropna()
    if series.empty:
        raise ValueError(f"No valid datetime entries found under {date_column}")
    return series


def build_monthly_count_chart(
    df: pd.DataFrame,
    *,
    date_column: str = "published",
    title: str = "Monthly CVE publication trend",
) -> Figure:
    """
    Build a simple bar chart showing CVE counts per month.
    """
    series = _normalize_datetimes(df, date_column)
    months = series.dt.to_period("M").dt.to_timestamp()
    summary = (
        months.value_counts()
        .sort_index()
        .rename_axis("month")
        .reset_index(name="count")
    )
    fig = px.bar(
        summary,
        x="month",
        y="count",
        labels={"month": "Month", "count": "CVE Count"},
        title=title,
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))
    return fig


def build_dayofweek_chart(
    df: pd.DataFrame,
    *,
    date_column: str = "published",
    title: str = "Day-of-week distribution",
) -> Figure:
    """
    Show how many CVEs were published for each weekday.
    """
    series = _normalize_datetimes(df, date_column)
    summary = (
        series.dt.day_name()
        .value_counts()
        .reindex(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"], fill_value=0)
        .rename_axis("weekday")
        .reset_index(name="count")
    )
    fig = px.bar(
        summary,
        x="weekday",
        y="count",
        labels={"weekday": "Weekday", "count": "CVE Count"},
        title=title,
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))
    return fig


def build_hourly_chart(
    df: pd.DataFrame,
    *,
    date_column: str = "published",
    title: str = "Hourly publication distribution",
) -> Figure:
    """
    Visualize CVE publication counts per hour of day.
    """
    series = _normalize_datetimes(df, date_column)
    summary = (
        series.dt.hour.value_counts()
        .sort_index()
        .rename_axis("hour")
        .reset_index(name="count")
    )
    fig = px.bar(
        summary,
        x="hour",
        y="count",
        labels={"hour": "Hour (UTC)", "count": "CVE Count"},
        title=title,
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))
    return fig


__all__ = [
    "DEFAULT_SCORE_BINS",
    "SEVERITY_ORDER",
    "build_cvss_score_bin_chart",
    "build_cvss_severity_chart",
    "build_dayofweek_chart",
    "build_hourly_chart",
    "build_monthly_count_chart",
    "extract_cvss_metrics",
    "summarize_cvss_availability",
]
