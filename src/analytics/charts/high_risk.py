from __future__ import annotations

from typing import Iterable, Optional, Sequence

import pandas as pd
import plotly.express as px
from plotly.graph_objects import Figure


# -----------------------------------------------------------------------------
# 내부 유틸리티
# -----------------------------------------------------------------------------

def _flag_high_risk(
    df: pd.DataFrame,
    severity_threshold: Sequence[str] = ("CRITICAL", "HIGH"),
) -> pd.Series:
    """
    CVSS baseSeverity 또는 CISA KEV 등재 여부로 고위험 여부를 판정한다.
    """
    severity_threshold = tuple(level.upper() for level in severity_threshold)

    def _highest_severity(metrics: object) -> Optional[str]:
        if not isinstance(metrics, dict):
            return None
        severities: list[str] = []
        for entries in metrics.values():
            if not isinstance(entries, Iterable):
                continue
            for item in entries:
                if not isinstance(item, dict):
                    continue
                cvss = item.get("cvssData", {})
                severity = cvss.get("baseSeverity") or item.get("baseSeverity")
                if severity:
                    severities.append(str(severity).upper())
        priority = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")
        for level in priority:
            if level in severities:
                return level
        return None

    def _evaluate(row: pd.Series) -> bool:
        if pd.notna(row.get("cisaExploitAdd")):
            return True
        severity = _highest_severity(row.get("metrics"))
        return severity in severity_threshold if severity else False

    return df.apply(_evaluate, axis=1)


def _extract_vendor(cpe_entry: object) -> Optional[str]:
    uri = None
    if isinstance(cpe_entry, dict):
        uri = cpe_entry.get("cpeName") or cpe_entry.get("criteria")
    elif isinstance(cpe_entry, str):
        uri = cpe_entry
    if not uri:
        return None
    parts = uri.split(":")
    return parts[3] if len(parts) > 4 else None


def _extract_product(cpe_entry: object) -> Optional[str]:
    uri = None
    if isinstance(cpe_entry, dict):
        uri = cpe_entry.get("cpeName") or cpe_entry.get("criteria")
    elif isinstance(cpe_entry, str):
        uri = cpe_entry
    if not uri:
        return None
    parts = uri.split(":")
    return parts[4] if len(parts) > 5 else None


def _explode_list_column(df: pd.DataFrame, column: str) -> pd.Series:
    exploded = df[column].explode().dropna()
    return exploded


def _summarize_counts(series: pd.Series, label: str, top_n: int) -> pd.DataFrame:
    counts = series.value_counts().head(top_n)
    summary = counts.reset_index()
    summary.columns = [label, "count"]
    return summary


def _build_bar_chart(summary_df: pd.DataFrame, x_col: str, title: str) -> Figure:
    fig = px.bar(
        summary_df,
        x=x_col,
        y="count",
        labels={x_col: x_col.capitalize(), "count": "High-Risk CVE Count"},
        title=title,
    )
    fig.update_layout(margin=dict(l=40, r=20, t=60, b=40))
    return fig


# -----------------------------------------------------------------------------
# 벤더별 고위험 분석
# -----------------------------------------------------------------------------

def summarize_high_risk_by_vendor(
    df: pd.DataFrame,
    *,
    top_n: int = 15,
    severity_threshold: Sequence[str] = ("CRITICAL", "HIGH"),
) -> pd.DataFrame:
    mask = _flag_high_risk(df, severity_threshold=severity_threshold)
    subset = df.loc[mask, ["cpes"]].dropna()
    if subset.empty:
        return pd.DataFrame(columns=["vendor", "count"])
    vendors = _explode_list_column(subset, "cpes").map(_extract_vendor).dropna()
    return _summarize_counts(vendors, "vendor", top_n)


def build_high_risk_vendor_chart(summary_df: pd.DataFrame, title: str = "High-Risk Vendors") -> Figure:
    if summary_df.empty:
        return px.bar(title=f"{title} (No data)")
    return _build_bar_chart(summary_df, "vendor", title)


# -----------------------------------------------------------------------------
# 제품별 고위험 분석
# -----------------------------------------------------------------------------

def summarize_high_risk_by_product(
    df: pd.DataFrame,
    *,
    top_n: int = 15,
    severity_threshold: Sequence[str] = ("CRITICAL", "HIGH"),
) -> pd.DataFrame:
    mask = _flag_high_risk(df, severity_threshold=severity_threshold)
    subset = df.loc[mask, ["cpes"]].dropna()
    if subset.empty:
        return pd.DataFrame(columns=["product", "count"])
    products = _explode_list_column(subset, "cpes").map(_extract_product).dropna()
    return _summarize_counts(products, "product", top_n)


def build_high_risk_product_chart(summary_df: pd.DataFrame, title: str = "High-Risk Products") -> Figure:
    if summary_df.empty:
        return px.bar(title=f"{title} (No data)")
    return _build_bar_chart(summary_df, "product", title)


# -----------------------------------------------------------------------------
# CWE별 고위험 분석
# -----------------------------------------------------------------------------

def summarize_high_risk_by_cwe(
    df: pd.DataFrame,
    *,
    top_n: int = 15,
    severity_threshold: Sequence[str] = ("CRITICAL", "HIGH"),
) -> pd.DataFrame:
    mask = _flag_high_risk(df, severity_threshold=severity_threshold)
    subset = df.loc[mask, ["cwes"]].dropna()
    if subset.empty:
        return pd.DataFrame(columns=["cweId", "count"])
    cwes = _explode_list_column(subset, "cwes").map(lambda item: item.get("cweId") if isinstance(item, dict) else None).dropna()
    return _summarize_counts(cwes, "cweId", top_n)


def build_high_risk_cwe_chart(summary_df: pd.DataFrame, title: str = "High-Risk CWEs") -> Figure:
    if summary_df.empty:
        return px.bar(title=f"{title} (No data)")
    return _build_bar_chart(summary_df, "cweId", title)


__all__ = [
    "summarize_high_risk_by_vendor",
    "summarize_high_risk_by_product",
    "summarize_high_risk_by_cwe",
    "build_high_risk_vendor_chart",
    "build_high_risk_product_chart",
    "build_high_risk_cwe_chart",
]
