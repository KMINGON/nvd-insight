from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import json
import sys
from datetime import datetime
import re
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
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
    "skrScore",
]
CISA_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SEVERITY_COLOR_MAP = {
    "CRITICAL": "#d62728",
    "HIGH": "#ff7f0e",
    "MEDIUM": "#ffbf00",
    "LOW": "#1f77b4",
    "UNKNOWN": "#8c8c8c",
}
BAND_COLOR_MAP = {
    "Low (0-5)": "#1f77b4",
    "Medium (5-8)": "#ffbf00",
    "High (8-10)": "#ff7f0e",
    "Critical+ (10+)": "#d62728",
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SKR_SCORE_BANDS = [
    "Low (0-5)",
    "Medium (5-8)",
    "High (8-10)",
    "Critical+ (10+)",
]


# 기능: 연도 입력값을 문자열 리스트로 정규화해 키/로딩에 재사용한다.
# 매개변수: years(연도 시퀀스 또는 None) - 정수/문자열 혼용 가능.
# 반환: 선택 연도를 문자열로 정렬한 리스트.
def normalize_years(years: Sequence[str] | None) -> List[str]:
    if years is None:
        return list(YEAR_CHOICES)
    return [str(year) for year in years]


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


# 기능: CISA exploit 데이터가 유효한 날짜 문자열인지 검사한다.
# 매개변수: value(CISA exploit 원본 값).
# 반환: YYYY-MM-dd 형식을 만족하는 경우 True, 아니면 False.
def _has_valid_cisa_flag(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (datetime, pd.Timestamp)):
        return True
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate or candidate.lower() == "null":
            return False
        if not CISA_DATE_PATTERN.match(candidate):
            return False
        try:
            datetime.strptime(candidate, "%Y-%m-%d")
            return True
        except ValueError:
            return False
    return False

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
        return pd.DataFrame(columns=TOP10_COLUMNS + ["cisaFlag"])

    rows: List[dict] = []
    for record in source_df.to_dict(orient="records"):
        payload = extract_cvss_payload(record)
        if not payload:
            continue
        raw_cisa = record.get("cisaExploitAdd")
        cisa_valid = _has_valid_cisa_flag(raw_cisa)
        cisa_flag = 1 if cisa_valid else 0
        rows.append(
            {
                "cveId": record.get("cveId"),
                "published": pd.to_datetime(record.get("published"), errors="coerce"),
                "description": record.get("description") or "",
                "baseSeverity": payload["baseSeverity"],
                "baseScore": payload["baseScore"],
                "cvss": payload.get("cvss"),
                "exploitabilityScore": payload.get("exploitabilityScore", 0.0),
                "cisaExploitAdd": raw_cisa if cisa_valid else None,
                "cisaFlag": cisa_flag,
                "cpes": record.get("cpes"),
                "cwes": record.get("cwes"),
            }
        )

    if not rows:
        return pd.DataFrame(columns=TOP10_COLUMNS + ["cisaFlag"])

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
    return selected.drop(columns=["cisaFlag"], errors="ignore")

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
        y="skrScore",
        color="baseSeverity",
        color_discrete_map=SEVERITY_COLOR_MAP,
        hover_data={
            "cveId": True,
            "baseSeverity": True,
            "baseScore": True,
            "skrScore": True,
            "exploitabilityScore": True,
            "cisaExploitAdd": True,
            "published": True,
        },
        title="Top 10 CVEs",
    )
    fig.update_layout(
        xaxis_title="CVE ID",
        yaxis_title="SKR Score",
        yaxis=dict(range=[0, 12]),
        bargap=0.2,
        margin=dict(l=60, r=40, t=80, b=120),
    )
    return fig


# 기능: Top10 CVE를 시간축으로 표시하는 산점도 차트를 생성한다.
# 매개변수: df(build_top10_dataset에서 반환된 DataFrame).
# 반환: Plotly Figure 객체.
def build_top10_timeline_chart(df: pd.DataFrame):
    if df.empty:
        fig = px.scatter(title="Top 10 CVE Timeline (데이터 없음)")
        fig.add_annotation(text="데이터가 없습니다", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        return fig

    timeline_df = df.copy()
    timeline_df["published"] = pd.to_datetime(timeline_df["published"], errors="coerce")
    timeline_df = timeline_df.dropna(subset=["published"])
    if timeline_df.empty:
        fig = px.scatter(title="Top 10 CVE Timeline (게시일 없음)")
        fig.add_annotation(text="게시일 정보가 없습니다", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        return fig

    fig = px.scatter(
        timeline_df,
        x="published",
        y="skrScore",
        size="baseScore",
        color="baseSeverity",
        color_discrete_map=SEVERITY_COLOR_MAP,
        hover_data={
            "cveId": True,
            "baseSeverity": True,
            "baseScore": True,
            "skrScore": True,
            "published": True,
        },
        text="cveId",
        title="올해 반드시 주의해야 할 상위 10대 취약점 타임라인",
    )
    fig.update_traces(textposition="top center")
    fig.update_layout(
        xaxis_title="발표일",
        yaxis_title="SKR Score (실제 위험도 점수)",
        yaxis=dict(range=[0, 12]),
        margin=dict(l=60, r=40, t=80, b=80),
    )
    return fig


# 기능: baseSeverity별 CISA 악용 여부 분포를 요약한다.
def summarize_severity_cisa(df: pd.DataFrame) -> pd.DataFrame:
    enriched = _prepare_skr_enriched(df)
    if enriched.empty:
        return pd.DataFrame(columns=["baseSeverity", "cisaLabel", "count", "avgSkrScore"])

    working = enriched.copy()
    working["baseSeverity"] = working["baseSeverity"].fillna("UNKNOWN").str.upper()
    working["cisaLabel"] = working["cisaFlag"].apply(lambda flag: "악용됨" if int(flag or 0) else "미확인")
    summary = (
        working.groupby(["baseSeverity", "cisaLabel"], as_index=False)
        .agg(count=("cveId", "size"), avgSkrScore=("skrScore", "mean"))
    )
    summary["avgSkrScore"] = summary["avgSkrScore"].fillna(0.0)
    summary["order"] = summary["baseSeverity"].apply(
        lambda value: SEVERITY_ORDER.index(value) if value in SEVERITY_ORDER else len(SEVERITY_ORDER)
    )
    summary = summary.sort_values(by=["order", "cisaLabel"], ascending=[True, True]).drop(columns="order")
    return summary.reset_index(drop=True)


# 기능: Severity별 악용 여부 집계를 듀얼축 막대 차트로 표현한다.
# 매개변수: summary_df(summarize_severity_cisa 결과 DataFrame).
# 반환: Plotly Figure 객체.
def build_severity_cisa_chart(summary_df: pd.DataFrame):
    if summary_df.empty:
        fig = go.Figure()
        fig.update_layout(title="Severity vs Exploitability (데이터 없음)")
        fig.add_annotation(text="데이터가 없습니다", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        return fig

    pivot = summary_df.pivot_table(
        index="baseSeverity",
        columns="cisaLabel",
        values="count",
        aggfunc="sum",
        fill_value=0,
    )
    pivot = pivot.reindex(SEVERITY_ORDER, fill_value=0)
    severities = [severity for severity in SEVERITY_ORDER if severity in pivot.index]
    if not severities:
        severities = list(pivot.index)

    counts_unknown = pivot.get("미확인", pd.Series(0, index=pivot.index)).loc[severities].tolist()
    counts_exploited = pivot.get("악용됨", pd.Series(0, index=pivot.index)).loc[severities].tolist()

    fig = go.Figure()
    fig.add_bar(
        x=severities,
        y=counts_unknown,
        name="미확인",
        marker_color="#1f77b4",
        offsetgroup="unknown",
    )
    fig.add_bar(
        x=severities,
        y=counts_exploited,
        name="악용됨",
        marker_color="#d62728",
        offsetgroup="exploited",
        yaxis="y2",
    )
    fig.update_layout(
        title="심각도와 실제 악용의 관계",
        barmode="group",
        bargap=0.25,
        legend_title="CISA 악용 여부",
        margin=dict(l=60, r=40, t=80, b=80),
        xaxis=dict(title="CVSS Severity"),
        yaxis=dict(title="CVE 개수 (미확인)", rangemode="tozero"),
        yaxis2=dict(title="CVE 개수 (악용됨)", overlaying="y", side="right", rangemode="tozero"),
    )
    return fig


# 기능: SKR Score 위험도 구간별 분포를 요약하고 시각화 데이터로 반환한다.
def summarize_skr_band_distribution(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    enriched = _prepare_skr_enriched(df)
    if enriched.empty:
        empty_counts = pd.DataFrame(columns=["band", "cisaLabel", "count"])
        empty_summary = pd.DataFrame(columns=["band", "count", "ratio", "exploited"])
        return empty_counts, empty_summary

    working = enriched.dropna(subset=["skrScore"]).copy()
    bins = [-0.01, 5, 8, 10, float("inf")]
    working["band"] = pd.cut(
        working["skrScore"],
        bins=bins,
        labels=SKR_SCORE_BANDS,
        right=False,
        include_lowest=True,
    )
    working = working.dropna(subset=["band"])
    working["cisaLabel"] = working["cisaFlag"].apply(lambda flag: "악용됨" if int(flag or 0) else "미확인")
    counts = (
        working.groupby(["band", "cisaLabel"], as_index=False, observed=True)
        .agg(count=("cveId", "size"))
    )
    counts["band"] = counts["band"].astype(str)
    counts["band"] = pd.Categorical(counts["band"], categories=SKR_SCORE_BANDS, ordered=True)
    counts = counts.sort_values("band").reset_index(drop=True)

    summary = (
        working.groupby("band", as_index=False, observed=True)
        .agg(count=("cveId", "size"), exploited=("cisaFlag", "sum"))
    )
    total = summary["count"].sum() or 1
    summary["ratio"] = summary["count"] / total
    summary["band"] = summary["band"].astype(str)
    summary["band"] = pd.Categorical(summary["band"], categories=SKR_SCORE_BANDS, ordered=True)
    summary = summary.sort_values("band").reset_index(drop=True)
    return counts, summary


# 기능: 위험도 구간별 전체 비중을 도넛 차트로 표현한다.
# 매개변수: summary_df(summarize_skr_band_distribution의 요약 DF).
# 반환: Plotly Figure 객체.
def build_skr_band_pie_chart(summary_df: pd.DataFrame):
    if summary_df.empty:
        fig = px.pie(title="SKR Score Band 분포 (데이터 없음)")
        fig.add_annotation(text="데이터가 없습니다", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        return fig

    fig = px.pie(
        summary_df,
        names="band",
        values="count",
        color="band",
        color_discrete_map=BAND_COLOR_MAP,
        category_orders={"band": SKR_SCORE_BANDS},
        hole=0.35,
        title="SKR Score 위험도 구간 비중",
    )
    fig.update_traces(textinfo="percent+label", hovertemplate="%{label}<br>건수: %{value}<br>비율: %{percent}")
    fig.update_layout(margin=dict(l=40, r=40, t=80, b=40))
    return fig


# 기능: 구간별 건수(막대)와 악용 비율(선)을 듀얼축으로 동시에 보여준다.
# 매개변수: summary_df(summarize_skr_band_distribution의 요약 DF).
# 반환: Plotly Figure 객체.
def build_skr_band_dual_axis_chart(summary_df: pd.DataFrame):
    if summary_df.empty:
        fig = go.Figure()
        fig.update_layout(title="SKR Score Band 악용 비중 (데이터 없음)")
        fig.add_annotation(text="데이터가 없습니다", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        return fig

    working = summary_df.copy()
    working["exploited_ratio"] = working.apply(
        lambda row: (row["exploited"] / row["count"]) if row["count"] else 0.0,
        axis=1,
    )
    working = working.sort_values("band")
    fig = go.Figure()
    fig.add_bar(
        x=working["band"],
        y=working["count"],
        name="CVE 건수",
        marker_color="#1f77b4",
        yaxis="y1",
    )
    fig.add_trace(
        go.Scatter(
            x=working["band"],
            y=working["exploited_ratio"],
            name="악용 비율",
            mode="lines+markers",
            line=dict(color="#d62728", width=2),
            marker=dict(size=8),
            yaxis="y2",
        )
    )
    fig.update_layout(
        title="구간별 건수 vs 악용 비율",
        xaxis=dict(title="SKR Score 구간", categoryorder="array", categoryarray=SKR_SCORE_BANDS),
        yaxis=dict(title="CVE 건수", rangemode="tozero"),
        yaxis2=dict(title="악용 비율", overlaying="y", side="right", tickformat=".0%", rangemode="tozero"),
        legend=dict(orientation="h", y=-0.2, x=0.5, xanchor="center"),
        margin=dict(l=60, r=60, t=80, b=80),
    )
    return fig


# 기능: 악용 보고된 취약점에 대해 발행→악용까지 걸린 일수를 계산한다.
def summarize_days_to_exploit(df: pd.DataFrame) -> pd.DataFrame:
    enriched = _prepare_skr_enriched(df)
    if enriched.empty:
        return pd.DataFrame(columns=["cveId", "baseSeverity", "published", "days_to_exploit"])

    working = enriched.copy()
    working = working[working["cisaFlag"] == 1]
    if working.empty:
        return pd.DataFrame(columns=["cveId", "baseSeverity", "published", "days_to_exploit"])

    published = pd.to_datetime(working["published"], errors="coerce")
    cisa_dates = pd.to_datetime(working["cisaExploitAdd"], errors="coerce")
    delta = (cisa_dates - published).dt.days
    working = working.assign(
        days_to_exploit=delta,
        published=published,
    )
    working = working.dropna(subset=["days_to_exploit"])
    working = working[working["days_to_exploit"] >= 0]
    working["baseSeverity"] = working["baseSeverity"].fillna("UNKNOWN").str.upper()
    return working[["cveId", "baseSeverity", "published", "days_to_exploit"]].reset_index(drop=True)


# 기능: 악용까지 걸린 일수 분포를 Severity별 누적 막대로 시각화한다.
# 매개변수: summary_df(summarize_days_to_exploit 결과 DataFrame).
# 반환: Plotly Figure 객체.
def build_days_to_exploit_histogram(summary_df: pd.DataFrame):
    if summary_df.empty:
        fig = px.histogram(title="악용까지 걸린 시간 분포 (데이터 없음)")
        fig.add_annotation(text="악용 데이터가 없습니다", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        return fig

    fig = px.histogram(
        summary_df,
        x="days_to_exploit",
        color="baseSeverity",
        category_orders={"baseSeverity": SEVERITY_ORDER},
        color_discrete_map=SEVERITY_COLOR_MAP,
        nbins=30,
        marginal="rug",
        histnorm="",
        title="악용까지 걸린 시간 분포",
    )
    fig.update_traces(opacity=0.85)
    fig.update_layout(
        xaxis_title="발표 후 악용까지 걸린 일수",
        yaxis_title="취약점 수",
        barmode="stack",
        legend_title="CVSS Severity",
        margin=dict(l=60, r=40, t=80, b=60),
    )
    return fig


# 기능: 악용까지 걸린 시간 분포를 KDE/등고선으로 표현한다.
# 매개변수: summary_df(summarize_days_to_exploit 결과 DataFrame).
# 반환: Plotly Figure 객체.
def build_days_to_exploit_kde(summary_df: pd.DataFrame):
    if summary_df.empty:
        fig = px.density_contour(title="악용까지 걸린 시간 KDE (데이터 없음)")
        fig.add_annotation(text="악용 데이터가 없습니다", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        return fig

    fig = px.density_contour(
        summary_df,
        x="days_to_exploit",
        title="악용까지 걸린 시간 KDE",
    )
    fig.update_traces(contours_coloring="fill", contours_showlabels=True)
    fig.update_layout(
        xaxis=dict(title="발표 후 악용까지 걸린 일수", range=[0, 300]),
        yaxis_title="밀도",
        margin=dict(l=40, r=20, t=60, b=60),
    )
    return fig


# 기능: Severity별 악용까지 걸린 일수 분포를 박스플롯으로 요약한다.
# 매개변수: summary_df(summarize_days_to_exploit 결과 DataFrame).
# 반환: Plotly Figure 객체.
def build_days_to_exploit_box(summary_df: pd.DataFrame):
    if summary_df.empty:
        fig = px.box(title="Severity별 악용까지 걸린 시간 (데이터 없음)")
        fig.add_annotation(text="악용 데이터가 없습니다", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        return fig

    fig = px.box(
        summary_df,
        x="baseSeverity",
        y="days_to_exploit",
        category_orders={"baseSeverity": SEVERITY_ORDER},
        color="baseSeverity",
        color_discrete_map=SEVERITY_COLOR_MAP,
        points="outliers",
        title="Severity별 악용까지 걸린 시간",
    )
    fig.update_layout(
        xaxis_title="CVSS Severity",
        yaxis_title="일수",
        margin=dict(l=60, r=40, t=80, b=60),
        showlegend=False,
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
def build_vendor_score_chart(summary_df: pd.DataFrame, title: str | None = None, threshold: float | None = None):
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
    label = f"skrScore >= {threshold:g} 건수" if threshold is not None else "skrScore >= 7 건수"
    fig.update_layout(xaxis_title="Vendor", yaxis_title=label)
    return fig

# 기능: product 요약 DataFrame을 Plotly 막대 차트로 표현한다.
# 매개변수: summary_df(summarize_product_counts 결과), title(선택 제목 문자열).
# 반환: Plotly Figure 객체.
def build_product_score_chart(summary_df: pd.DataFrame, title: str | None = None, threshold: float | None = None):
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
    label = f"skrScore >= {threshold:g} 건수" if threshold is not None else "skrScore >= 7 건수"
    fig.update_layout(xaxis_title="Product", yaxis_title=label)
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
def build_cwe_score_chart(summary_df: pd.DataFrame, title: str | None = None, threshold: float | None = None):
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
    label = f"skrScore >= {threshold:g} 건수" if threshold is not None else "skrScore >= 7 건수"
    fig.update_layout(xaxis_title="CWE ID", yaxis_title=label)
    return fig
