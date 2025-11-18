from __future__ import annotations                                                                           
                                                                                                               
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# 기본적으로 NVD CVE 피드(JSON 파일)들이 저장된 디렉터리 경로
RAW_CVE_DIR = Path(__file__).resolve().parents[2] / "data" / "raw" / "cve"
                                                                                                               
                                                                                                               
@st.cache_data(show_spinner=False)
def load_published_dates(raw_dir: Path = RAW_CVE_DIR) -> pd.DataFrame:
    """Load all published dates from NVD feed JSON files into a clean DataFrame."""

    records: list[dict] = []

     # 각 NVD JSON 파일을 순회하면서 CVE 공개일(published)을 수집
    for feed_path in sorted(raw_dir.glob("nvdcve-2.0-*.json")):
        with feed_path.open("r", encoding="utf-8") as fh:
            feed = json.load(fh)
        # vulnerabilities 리스트 안에서 cve published 필드 추출
        for entry in feed.get("vulnerabilities", []):
            cve = entry.get("cve", {})
            published = cve.get("published")
            if published:
                records.append({"cveId": cve.get("id"), "published": published})

    df = pd.DataFrame(records)

    # 날짜(datetime) 형식으로 변환, 오류는 NaT 처리 → published 없는 행 제거
    df["published"] = pd.to_datetime(df["published"], errors="coerce")
    df = df.dropna(subset=["published"])
    # 연도/월 정보를 쉽게 집계할 수 있도록 year, month 컬럼 생성
    df["year"] = df["published"].dt.to_period("Y").dt.to_timestamp()
    df["month"] = df["published"].dt.to_period("M").dt.to_timestamp()
    return df
                                                                                                               
                                                                                                               
def plot_counts(df: pd.DataFrame, granularity: str = "year") -> px.bar:
    """Aggregate by year or month and return a Plotly bar chart."""

    column = "year" if granularity == "year" else "month"
    # 연도별/월별 CVE 개수 집계
    counts = (
        df.groupby(column)
        .size()
        .reset_index(name="cveCount")
        .sort_values(column)
    )
    title = "CVE Published Trend by Year" if column == "year" else "CVE Published Trend by Month"
    fig = px.line(
        counts,
        x=column,
        y="cveCount",
        markers=True,  # 점 표시
        labels={column: column.title(), "cveCount": "취약점 수"},
        title=title,
    )
    fig.update_traces(line=dict(width=3), marker=dict(size=6))

    fig.update_layout(
        margin=dict(l=20, r=20, t=60, b=40),
        xaxis_title="",
        yaxis_title="취약점 수",
        hovermode="x unified",
    )
    
    return fig
                                                                                                               
                                                                                                               
def main() -> None:
    """Streamlit entry point wiring up controls and visualization."""

    st.set_page_config(page_title="CVE Published Trend", layout="wide")
    st.title("CVE 월/연도별 추이 (published 기준)")
    # 모든 JSON 파일 로딩
    df = load_published_dates()
    st.metric("총 CVE 건수", f"{len(df):,}")

     # 집계 단위(연도/월) 선택
    granularity = st.radio(
        "집계 단위",
        options=("year", "month"),
        format_func=lambda x: "연도" if x == "year" else "월",
    )
    # 연도 범위 슬라이더 설정
    year_min, year_max = int(df["published"].dt.year.min()), int(df["published"].dt.year.max())
    year_range = st.slider(
        "연도 범위",
        min_value=year_min,
        max_value=year_max,
        value=(year_min, year_max),
    )
     # 연도 범위 필터 적용
    mask = df["published"].dt.year.between(*year_range)
    filtered = df[mask]

     # 그래프 출력
    fig = plot_counts(filtered, granularity=granularity)
    st.plotly_chart(fig, use_container_width=True)
                                                                                                               
                                                                                                               
if __name__ == "__main__":                                                                                   
    main()