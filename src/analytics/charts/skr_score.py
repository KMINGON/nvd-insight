from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import json
import sys
import pandas as pd
import plotly.express as px
import streamlit as st

try:
    from ...config import PROCESSED_DATASET_DIR
except ImportError:
    PROJECT_ROOT = Path(__file__).resolve().parents[3]
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from src.config import PROCESSED_DATASET_DIR
from ..base_loader import load_processed_dataframe

YEAR_CHOICES = ("2020", "2021", "2022", "2023", "2024", "2025")
TOP_K = 10
TOP10_COLUMNS = [
    "cveId",
    "published",
    "description",
    "baseSeverity",
    "baseScore",
    "cvss",
    "exploitabilityScore",
    "cisaExploitAdd",
]


# 기능: 연도 입력값을 문자열 리스트로 정규화해 키/로딩에 재사용한다.
# 매개변수: years(연도 시퀀스 또는 None) - 정수/문자열 혼용 가능.
# 반환: 선택 연도를 문자열로 정렬한 리스트.
def normalize_years(years: Sequence[str] | None) -> List[str]:
    if years is None:
        return list(YEAR_CHOICES)
    return [str(year) for year in years]


# 기능: 특정 연도의 JSON 샤드를 읽어 CVE 레코드 리스트로 반환한다.
# 매개변수: year(문자열 연도), dataset_dir(JSON 파일들이 위치한 디렉터리 Path).
# 반환: 연도별 레코드 딕셔너리 리스트.
def load_records_for_year(year: str, dataset_dir: Path) -> List[dict]:
    shard = dataset_dir / f"cve_cwe_dataset_{year}.json"
    if not shard.exists():
        return []
    with shard.open("r", encoding="utf-8") as fh:
        return json.load(fh)


# 기능: CPE 엔트리에서 vendor 문자열을 파싱한다.
# 매개변수: cpe_entry(dict 또는 문자열 형태의 CPE 데이터).
# 반환: vendor 문자열 또는 추출 불가 시 None.
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


# 기능: CPE 엔트리에서 product명을 추출한다.
# 매개변수: cpe_entry(dict 또는 문자열 형태의 CPE 데이터).
# 반환: product 문자열 또는 추출 불가 시 None.
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

# 기능: 레코드 내 CVSS 메트릭에서 심각도, 점수, 벡터를 추출한다.
# 매개변수: record(load_processed_dataframe 결과 행 딕셔너리).
# 반환: baseSeverity/baseScore/exploitabilityScore 등을 담은 dict 또는 None.
def extract_cvss_payload(record: dict) -> dict | None:
    for key in ("metrics.cvssMetricV40", "metrics.cvssMetricV31", "metrics.cvssMetricV30", "metrics.cvssMetricV2"):
        entries = record.get(key)
        if not isinstance(entries, (list, tuple)):
            continue
        for entry in entries:
            cvss_data = entry.get("cvssData") or {}
            severity = (cvss_data.get("baseSeverity") or entry.get("baseSeverity") or "").upper()
            if not severity:
                continue
            return {
                "baseSeverity": severity,
                "cvss": cvss_data.get("vectorString") or entry.get("vectorString"),
                "baseScore": float(cvss_data.get("baseScore") or entry.get("baseScore") or 0.0),
                "exploitabilityScore": float(entry.get("exploitabilityScore") or 0.0),
            }
    return None

# 기능: baseScore/Exploitability/CISA 플래그를 조합해 skrScore를 계산한다.
# 매개변수: base_score(float 또는 시리즈), exploit_score(float 또는 시리즈), cisa_flag(bool/정수 시리즈).
# 반환: 가중치 적용된 float 또는 시리즈 점수.
def compute_skr_score(base_score, exploit_score, cisa_flag) -> float:
    cisa_component = (
        2 * cisa_flag.astype(float)
        if isinstance(cisa_flag, pd.Series)
        else 2 * (1 if cisa_flag else 0)
    )
    return (0.6 * base_score) + (0.4 * exploit_score) + cisa_component

# 기능: 원본 DataFrame에 skrScore 및 CPE/CWE 메타 데이터를 추가한다.
# 매개변수: source_df(load_processed_dataframe 결과 또는 부분 DataFrame).
# 반환: skrScore, cisaFlag 등을 포함한 DataFrame.
def build_skr_score_added_df(source_df: pd.DataFrame | None) -> pd.DataFrame:
    if source_df is None or source_df.empty:
        return pd.DataFrame(columns=TOP10_COLUMNS + ["cisaFlag", "skrScore"])

    rows: List[dict] = []
    for record in source_df.to_dict(orient="records"):
        payload = extract_cvss_payload(record)
        if not payload:
            continue
        cisa_flag = 1 if record.get("cisaExploitAdd") else 0
        rows.append(
            {
                "cveId": record.get("cveId"),
                "published": pd.to_datetime(record.get("published"), errors="coerce"),
                "description": record.get("description") or "",
                "baseSeverity": payload["baseSeverity"],
                "baseScore": payload["baseScore"],
                "cvss": payload.get("cvss"),
                "exploitabilityScore": payload.get("exploitabilityScore", 0.0),
                "cisaExploitAdd": record.get("cisaExploitAdd"),
                "cisaFlag": cisa_flag,
                "cpes": record.get("cpes"),
                "cwes": record.get("cwes"),
            }
        )

    if not rows:
        return pd.DataFrame(columns=TOP10_COLUMNS + ["cisaFlag", "skrScore"])

    enriched = pd.DataFrame(rows)
    enriched["exploitabilityScore"] = enriched["exploitabilityScore"].fillna(0.0)
    enriched["cisaFlag"] = enriched["cisaFlag"].fillna(0).astype(int)
    enriched["skrScore"] = compute_skr_score(
        enriched["baseScore"],
        enriched["exploitabilityScore"],
        enriched["cisaFlag"],
    )
    return enriched

# 기능: 입력 DF가 skrScore 관련 필드를 갖춰 이미 계산되었는지 확인한다.
# 매개변수: df(skrScore 포함 여부를 확인할 DataFrame).
# 반환: 필수 컬럼 존재 여부(True/False).
def _is_skr_score_ready(df: pd.DataFrame | None) -> bool:
    if df is None or df.empty:
        return False
    required = {"cveId", "baseSeverity", "baseScore", "exploitabilityScore", "skrScore"}
    return required.issubset(df.columns)


# 기능: 원본 DF를 skrScore 컬럼이 포함된 형태로 변환한다.
# 매개변수: df(원본 또는 이미 계산된 DataFrame).
# 반환: skrScore가 포함된 DataFrame.
def _prepare_skr_enriched(df: pd.DataFrame | None) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame()
    return df if _is_skr_score_ready(df) else build_skr_score_added_df(df)


# 기능: skrScore DF에서 최고 점수 순 Top 10 레코드를 선택한다.
# 매개변수: enriched(skrScore 포함 DataFrame).
# 반환: Top 10 CVE 정보를 담은 DataFrame.
def _build_top10_from_enriched(enriched: pd.DataFrame) -> pd.DataFrame:
    if enriched is None or enriched.empty:
        return pd.DataFrame(columns=TOP10_COLUMNS)
    top_df = enriched.sort_values(by="skrScore", ascending=False)
    selected = top_df.drop_duplicates(subset="cveId").head(TOP_K).reset_index(drop=True)
    return selected.drop(columns=["cisaFlag", "skrScore"], errors="ignore")

# 기능: 연도 조합별 Top10 DataFrame을 캐시해 재사용한다.
# 매개변수: year_key(정렬된 연도 문자열 튜플).
# 반환: 캐시된 Top10 DataFrame.
@st.cache_data(show_spinner=False)
def _cached_top10_dataset(year_key: Tuple[str, ...]) -> pd.DataFrame:
    df = load_processed_dataframe(years=list(year_key))
    enriched = build_skr_score_added_df(df)
    return _build_top10_from_enriched(enriched)

# 기능: 연도 또는 전달된 DF를 기반으로 skrScore Top10을 생성한다.
# 매개변수: years(데이터 로드를 위한 연도 목록), source_df(이미 로드된 DataFrame).
# 반환: Top 10 CVE 정보를 담은 DataFrame.
def build_top10_dataset(
    years: Sequence[str] | None = None,
    source_df: pd.DataFrame | None = None,
) -> pd.DataFrame:
    if source_df is None and years:
        year_key = tuple(sorted(normalize_years(years)))
        return _cached_top10_dataset(year_key).copy(deep=True)

    df = source_df.copy() if source_df is not None else load_processed_dataframe(years=years)
    enriched = _prepare_skr_enriched(df)
    return _build_top10_from_enriched(enriched)

# 기능: Top10 DataFrame을 Plotly 막대 차트로 시각화한다.
# 매개변수: df(build_top10_dataset에서 반환된 DataFrame).
# 반환: Plotly Figure 객체.
def build_top10_chart(df: pd.DataFrame):
    if df.empty:
        fig = px.bar(title="Top 10 CVEs (데이터 없음)")
        fig.add_annotation(text="데이터가 없습니다", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        return fig

    fig = px.bar(
        df,
        x="cveId",
        y="baseScore",
        color="baseSeverity",
        color_discrete_map={"CRITICAL": "#d62728", "HIGH": "#ff7f0e"},
        hover_data={
            "cveId": True,
            "baseSeverity": True,
            "baseScore": True,
            "exploitabilityScore": True,
            "cisaExploitAdd": True,
            "published": True,
        },
        title="Top 10 CVEs",
    )
    fig.update_layout(
        xaxis_title="CVE ID",
        yaxis_title="CVSS Base Score",
        yaxis=dict(range=[0, 10]),
        bargap=0.2,
        margin=dict(l=60, r=40, t=80, b=120),
    )
    return fig

# 기능: skrScore 임계값을 넘는 레코드를 vendor 기준으로 집계한다.
# 매개변수: df(skrScore 포함 DF), top_n(상위 표출 수), threshold(skrScore 필터 값).
# 반환: vendor, count, score가 포함된 DataFrame.
def summarize_vendor_counts(df: pd.DataFrame, top_n: int = 5, threshold: float = 7.0) -> pd.DataFrame:
    enriched = _prepare_skr_enriched(df)
    if enriched.empty:
        return pd.DataFrame(columns=["vendor", "count", "score"])

    scores: Dict[str, float] = {}
    counts: Dict[str, int] = {}
    for record in enriched.to_dict(orient="records"):
        row_score = record.get("skrScore")
        if row_score is None or pd.isna(row_score) or row_score <= threshold:
            continue
        cpes = record.get("cpes")
        if not isinstance(cpes, list):
            continue
        seen_vendors = set()
        for cpe in cpes:
            vendor = _extract_vendor(cpe)
            if not vendor or vendor in seen_vendors:
                continue
            seen_vendors.add(vendor)
            counts[vendor] = counts.get(vendor, 0) + 1
            scores[vendor] = scores.get(vendor, 0.0) + float(row_score)
    if not counts:
        return pd.DataFrame(columns=["vendor", "count", "score"])
    summary = pd.DataFrame(
        [
            {
                "vendor": vendor,
                "count": counts[vendor],
                "score": scores.get(vendor, 0.0),
            }
            for vendor in counts
        ]
    )
    summary = summary.sort_values(by=["count", "score"], ascending=False).head(top_n)
    return summary.reset_index(drop=True)

# 기능: skrScore 임계값을 넘는 레코드를 product 기준으로 집계한다.
# 매개변수: df(skrScore 포함 DF), top_n(상위 표출 수), threshold(skrScore 필터 값).
# 반환: product, count, score가 포함된 DataFrame.
def summarize_product_counts(df: pd.DataFrame, top_n: int = 5, threshold: float = 7.0) -> pd.DataFrame:
    enriched = _prepare_skr_enriched(df)
    if enriched.empty:
        return pd.DataFrame(columns=["product", "count", "score"])

    scores: Dict[str, float] = {}
    counts: Dict[str, int] = {}
    for record in enriched.to_dict(orient="records"):
        row_score = record.get("skrScore")
        if row_score is None or pd.isna(row_score) or row_score <= threshold:
            continue
        cpes = record.get("cpes")
        if not isinstance(cpes, list):
            continue
        seen_products = set()
        for cpe in cpes:
            product = _extract_product(cpe)
            if not product or product in seen_products:
                continue
            seen_products.add(product)
            counts[product] = counts.get(product, 0) + 1
            scores[product] = scores.get(product, 0.0) + float(row_score)
    if not counts:
        return pd.DataFrame(columns=["product", "count", "score"])
    summary = pd.DataFrame(
        [
            {
                "product": product,
                "count": counts[product],
                "score": scores.get(product, 0.0),
            }
            for product in counts
        ]
    )
    summary = summary.sort_values(by=["count", "score"], ascending=False).head(top_n)
    return summary.reset_index(drop=True)

# 기능: vendor 요약 DataFrame을 Plotly 막대 차트로 시각화한다.
# 매개변수: summary_df(summarize_vendor_counts 결과), title(선택 제목 문자열).
# 반환: Plotly Figure 객체.
def build_vendor_score_chart(summary_df: pd.DataFrame, title: str | None = None):
    if summary_df.empty:
        fig = px.bar(title=title or "Vendor 데이터 없음")
        fig.add_annotation(text="데이터가 없습니다", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        return fig
    fig = px.bar(
        summary_df,
        x="vendor",
        y="count",
        title=title or "Top Vendors",
    )
    fig.update_layout(xaxis_title="Vendor", yaxis_title="skrScore >= 7 건수")
    return fig

# 기능: product 요약 DataFrame을 Plotly 막대 차트로 표현한다.
# 매개변수: summary_df(summarize_product_counts 결과), title(선택 제목 문자열).
# 반환: Plotly Figure 객체.
def build_product_score_chart(summary_df: pd.DataFrame, title: str | None = None):
    if summary_df.empty:
        fig = px.bar(title=title or "Product 데이터 없음")
        fig.add_annotation(text="데이터가 없습니다", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        return fig
    fig = px.bar(
        summary_df,
        x="product",
        y="count",
        title=title or "Top Products",
    )
    fig.update_layout(xaxis_title="Product", yaxis_title="skrScore >= 7 건수")
    return fig

# 기능: skrScore 임계값을 넘는 레코드를 CWE 기준으로 집계하고 설명을 포함한다.
# 매개변수: df(skrScore 포함 DF), top_n(상위 표출 수), threshold(skrScore 필터 값).
# 반환: cweId, count, score, 설명 필드가 포함된 DataFrame.
def summarize_cwe_scores(df: pd.DataFrame, top_n: int = 5, threshold: float = 7.0) -> pd.DataFrame:
    enriched = _prepare_skr_enriched(df)
    if enriched.empty:
        return pd.DataFrame(
            columns=[
                "cweId",
                "count",
                "score",
                "cweDescription",
                "cweExtendedDescription",
                "cweBackgroundDetails",
            ]
        )

    counts: Dict[str, int] = {}
    scores: Dict[str, float] = {}
    descriptions: Dict[str, str] = {}
    extended_desc: Dict[str, str] = {}
    background: Dict[str, str] = {}
    for record in enriched.to_dict(orient="records"):
        row_score = record.get("skrScore")
        if row_score is None or pd.isna(row_score) or row_score <= threshold:
            continue
        cwes = record.get("cwes")
        if not isinstance(cwes, list):
            continue
        for cwe in cwes:
            if isinstance(cwe, dict):
                cwe_id = cwe.get("cweId")
                if not cwe_id:
                    continue
                if cwe_id in {"NVD-CWE-noinfo", "NVD-CWE-Other"}:
                    continue
                descriptions.setdefault(cwe_id, cwe.get("cweDescription"))
                extended_desc.setdefault(cwe_id, cwe.get("cweExtendedDescription"))
                background.setdefault(cwe_id, cwe.get("cweBackgroundDetails"))
            else:
                cwe_id = None
            if not cwe_id:
                continue
            counts[cwe_id] = counts.get(cwe_id, 0) + 1
            scores[cwe_id] = scores.get(cwe_id, 0.0) + float(row_score)
    if not counts:
        return pd.DataFrame(
            columns=[
                "cweId",
                "count",
                "score",
                "cweDescription",
                "cweExtendedDescription",
                "cweBackgroundDetails",
            ]
        )
    summary = pd.DataFrame(
        [
            {
                "cweId": cwe_id,
                "count": counts[cwe_id],
                "score": scores.get(cwe_id, 0.0),
                "cweDescription": descriptions.get(cwe_id),
                "cweExtendedDescription": extended_desc.get(cwe_id),
                "cweBackgroundDetails": background.get(cwe_id),
            }
            for cwe_id in counts
        ]
    )
    summary = summary.sort_values(by=["count", "score"], ascending=False).head(top_n)
    return summary.reset_index(drop=True)

# 기능: CWE 요약 DataFrame을 Plotly 막대 차트로 가시화한다.
# 매개변수: summary_df(summarize_cwe_scores 결과), title(선택 제목 문자열).
# 반환: Plotly Figure 객체.
def build_cwe_score_chart(summary_df: pd.DataFrame, title: str | None = None):
    if summary_df.empty:
        fig = px.bar(title=title or "CWE 데이터 없음")
        fig.add_annotation(text="데이터가 없습니다", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        return fig
    fig = px.bar(
        summary_df,
        x="cweId",
        y="count",
        title=title or "Top CWEs",
    )
    fig.update_layout(xaxis_title="CWE ID", yaxis_title="skrScore >= 7 건수")
    return fig
