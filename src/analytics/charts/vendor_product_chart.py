from __future__ import annotations

from typing import Optional

import pandas as pd
import plotly.express as px
from plotly.graph_objects import Figure

CPE_COLUMN = "cpes"
CVE_ID_COLUMN = "cveId"


def parse_cpe_uri(criteria: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """
    Extract vendor/product segments from a CPE 2.3 URI string.
    """
    if not criteria or not isinstance(criteria, str):
        return (None, None)
    parts = criteria.split(":")
    if len(parts) < 6:
        return (None, None)
    vendor = parts[3] or None
    product = parts[4] or None
    return (vendor, product)


def explode_cpe_entries(
    df: pd.DataFrame,
    *,
    cpe_column: str = CPE_COLUMN,
    id_column: str = CVE_ID_COLUMN,
) -> pd.DataFrame:
    """
    Expand the CPE list column so vendor/product can be parsed per row.
    """
    if cpe_column not in df.columns:
        raise ValueError(f"{cpe_column} column missing from dataframe")
    if id_column not in df.columns:
        raise ValueError(f"{id_column} column missing from dataframe")

    frame = df[[id_column, cpe_column]].copy()
    frame[cpe_column] = frame[cpe_column].apply(lambda value: value if isinstance(value, list) else [])
    exploded = frame.explode(cpe_column).dropna(subset=[cpe_column])

    def _extract(rec: dict | None) -> tuple[Optional[str], Optional[str], Optional[str]]:
        if not isinstance(rec, dict):
            return (None, None, None)
        criteria = rec.get("criteria") or rec.get("cpeName")
        vendor, product = parse_cpe_uri(criteria)
        return (criteria, vendor, product)

    extracted = exploded[cpe_column].apply(_extract).to_list()
    extracted_df = pd.DataFrame(extracted, columns=["criteria", "vendor", "product"])
    result = pd.concat([exploded[[id_column]].reset_index(drop=True), extracted_df], axis=1)
    result = result.dropna(subset=["criteria"])
    return result


def summarize_vendor_counts(
    df: pd.DataFrame,
    *,
    top_n: int = 20,
    cpe_column: str = CPE_COLUMN,
    id_column: str = CVE_ID_COLUMN,
) -> pd.DataFrame:
    """
    Generate a top-N vendor frequency table based on CVE coverage.
    """
    exploded = explode_cpe_entries(df, cpe_column=cpe_column, id_column=id_column)
    valid = exploded.dropna(subset=["vendor"]).drop_duplicates([id_column, "vendor"])
    summary = (
        valid.groupby("vendor")[id_column]
        .nunique()
        .reset_index(name="cveCount")
        .sort_values("cveCount", ascending=False)
        .head(top_n)
    )
    return summary


def summarize_product_counts(
    df: pd.DataFrame,
    *,
    top_n: int = 20,
    cpe_column: str = CPE_COLUMN,
    id_column: str = CVE_ID_COLUMN,
) -> pd.DataFrame:
    """
    Generate a top-N product frequency table based on CVE coverage.
    """
    exploded = explode_cpe_entries(df, cpe_column=cpe_column, id_column=id_column)
    valid = exploded.dropna(subset=["product"]).drop_duplicates([id_column, "product"])
    summary = (
        valid.groupby("product")[id_column]
        .nunique()
        .reset_index(name="cveCount")
        .sort_values("cveCount", ascending=False)
        .head(top_n)
    )
    return summary


def build_vendor_bar_chart(
    df: pd.DataFrame,
    *,
    top_n: int = 20,
    title: str = "Top Vendors by CVE Count",
) -> Figure:
    """
    Bar chart representation of vendor frequency.
    """
    summary = summarize_vendor_counts(df, top_n=top_n)
    fig = px.bar(
        summary,
        x="cveCount",
        y="vendor",
        orientation="h",
        labels={"vendor": "Vendor", "cveCount": "CVE Count"},
        title=title,
    )
    fig.update_layout(yaxis=dict(autorange="reversed"), margin=dict(l=80, r=40, t=60, b=40))
    return fig


def build_product_bar_chart(
    df: pd.DataFrame,
    *,
    top_n: int = 20,
    title: str = "Top Products by CVE Count",
) -> Figure:
    """
    Bar chart representation of product frequency.
    """
    summary = summarize_product_counts(df, top_n=top_n)
    fig = px.bar(
        summary,
        x="cveCount",
        y="product",
        orientation="h",
        labels={"product": "Product", "cveCount": "CVE Count"},
        title=title,
    )
    fig.update_layout(yaxis=dict(autorange="reversed"), margin=dict(l=80, r=40, t=60, b=40))
    return fig


__all__ = [
    "build_product_bar_chart",
    "build_vendor_bar_chart",
    "explode_cpe_entries",
    "parse_cpe_uri",
    "summarize_product_counts",
    "summarize_vendor_counts",
]

