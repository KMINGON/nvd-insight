from __future__ import annotations

from typing import Optional

import pandas as pd
import plotly.express as px
from plotly.graph_objects import Figure

# CPE 정보가 들어있는 컬럼명
CPE_COLUMN = "cpes"
# CVE ID 컬럼명
CVE_ID_COLUMN = "cveId"


def parse_cpe_uri(criteria: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """
    CPE 2.3 URI 문자열에서 vendor, product 값을 추출하는 함수.
    예: cpe:2.3:a:microsoft:edge:... → vendor=microsoft, product=edge
    """
    if not criteria or not isinstance(criteria, str):   # 유효한 문자열인지 체크
        return (None, None)

    parts = criteria.split(":")   # ":" 기준으로 분해

    # CPE 2.3 표준 구조는 최소 6개 파트가 있어야 vendor/product 위치가 보장됨
    if len(parts) < 6:
        return (None, None)

    vendor = parts[3] or None     # vendor 위치
    product = parts[4] or None    # product 위치
    return (vendor, product)


def explode_cpe_entries(
    df: pd.DataFrame,
    *,
    cpe_column: str = CPE_COLUMN,
    id_column: str = CVE_ID_COLUMN,
) -> pd.DataFrame:
    """
    CPE 리스트(cpes)가 들어 있는 DataFrame을
    '한 CVE = 여러 CPE' 구조를 풀어서( explode )
    vendor/product 정보를 한 줄씩 독립적으로 매핑하는 함수.
    """
    # 필수 컬럼 존재 여부 체크
    if cpe_column not in df.columns:
        raise ValueError(f"{cpe_column} column missing from dataframe")
    if id_column not in df.columns:
        raise ValueError(f"{id_column} column missing from dataframe")

    # CVE ID + CPE 리스트만 추출
    frame = df[[id_column, cpe_column]].copy()

    # cpes 컬럼이 list가 아닐 경우 비어 있는 리스트로 대체
    frame[cpe_column] = frame[cpe_column].apply(lambda value: value if isinstance(value, list) else [])

    # 리스트를 행 단위로 펼침
    exploded = frame.explode(cpe_column).dropna(subset=[cpe_column])

    # 내부 dict → vendor/product 3개 필드로 변환하는 내부 함수
    def _extract(rec: dict | None) -> tuple[Optional[str], Optional[str], Optional[str]]:
        if not isinstance(rec, dict):
            return (None, None, None)

        # criteria 또는 cpeName 키 중 존재하는 값 사용
        criteria = rec.get("criteria") or rec.get("cpeName")

        # vendor/product 추출
        vendor, product = parse_cpe_uri(criteria)

        return (criteria, vendor, product)

    # explode된 CPE dict들을 한 번에 변환
    extracted = exploded[cpe_column].apply(_extract).to_list()

    # criteria/vendor/product를 가진 새로운 DataFrame 생성
    extracted_df = pd.DataFrame(extracted, columns=["criteria", "vendor", "product"])

    # CVE ID + vendor/product 조합으로 결합
    result = pd.concat([exploded[[id_column]].reset_index(drop=True), extracted_df], axis=1)

    # criteria 없는 행 제거
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
    vendor 기준으로 CVE 개수를 집계하여 상위 top_n만 반환하는 함수.
    """
    exploded = explode_cpe_entries(df, cpe_column=cpe_column, id_column=id_column)

    # vendor 값 있는 행만 사용 + 같은 (CVE, vendor) 조합 중복 제거
    valid = exploded.dropna(subset=["vendor"]).drop_duplicates([id_column, "vendor"])

    summary = (
        valid.groupby("vendor")[id_column]
        .nunique()                         # 각 vendor가 가진 CVE 수
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
    product 기준으로 CVE 개수를 집계하여 상위 top_n만 반환하는 함수.
    """
    exploded = explode_cpe_entries(df, cpe_column=cpe_column, id_column=id_column)

    # product 값 있는 행만 사용 + 중복 제거
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
    vendor별 CVE 개수를 막대그래프로 시각화.
    (수평 그래프, 상위 20개 기본)
    """
    summary = summarize_vendor_counts(df, top_n=top_n)

    # 수평 막대그래프 orientation="h"
    fig = px.bar(
        summary,
        x="cveCount",
        y="vendor",
        orientation="h",
        labels={"vendor": "Vendor", "cveCount": "CVE Count"},
        title=title,
    )
    # y축을 위→아래 순서가 아닌, 상위 vendor가 위로 오도록 reverse
    fig.update_layout(
        yaxis=dict(autorange="reversed"),
        margin=dict(l=80, r=40, t=60, b=40)
    )
    return fig


def build_product_bar_chart(
    df: pd.DataFrame,
    *,
    top_n: int = 20,
    title: str = "Top Products by CVE Count",
) -> Figure:
    """
    product별 CVE 개수를 막대그래프로 시각화.
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
    fig.update_layout(
        yaxis=dict(autorange="reversed"),
        margin=dict(l=80, r=40, t=60, b=40)
    )
    return fig


__all__ = [
    "build_product_bar_chart",
    "build_vendor_bar_chart",
    "explode_cpe_entries",
    "parse_cpe_uri",
    "summarize_product_counts",
    "summarize_vendor_counts",
]
