from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analytics.base_loader import load_processed_dataframe
from src.analytics.charts import (
    build_high_risk_cwe_chart,
    build_high_risk_product_chart,
    build_high_risk_vendor_chart,
    summarize_high_risk_by_cwe,
    summarize_high_risk_by_product,
    summarize_high_risk_by_vendor,
)
from src import config


def _available_years() -> List[int]:
    pattern = re.compile(r"cve_cwe_dataset_(\d{4})\.json")
    years = []
    for file in sorted(config.PROCESSED_DATASET_DIR.glob("cve_cwe_dataset_*.json")):
        match = pattern.search(file.name)
        if match:
            years.append(int(match.group(1)))
    return years


@st.cache_data(show_spinner=False)
def _load(years: tuple[int, ...]):
    return load_processed_dataframe(years=list(years))


def main() -> None:
    st.set_page_config(page_title="High-Risk Hotspots", layout="wide")
    st.title("고위험 집중 영역 분석")
    st.caption("CVSS severity 및 CISA KEV 등재 여부를 바탕으로 벤더/제품/CWE별 고위험 CVE 현황을 요약합니다.")

    years = _available_years()
    if not years:
        st.error("data/processed/cve_cwe_by_year/ 하위에서 연도별 JSON을 찾을 수 없습니다. build_dataset.py를 먼저 실행하세요.")
        return

    with st.sidebar:
        st.header("필터")
        default_years = [years[-1]]
        selected_years = st.multiselect("연도 선택", years, default=default_years)
        if not selected_years:
            selected_years = default_years
        severity_options = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        selected_severity = st.multiselect(
            "Severity Threshold",
            severity_options,
            default=["CRITICAL", "HIGH"],
            help="선택한 등급 이상이면 고위험으로 간주합니다.",
        )
        if not selected_severity:
            selected_severity = ["CRITICAL", "HIGH"]
        top_n = st.slider("Top N", min_value=5, max_value=25, value=10, step=1)

    df = _load(tuple(selected_years))
    st.success(f"{len(df):,}건의 CVE 데이터를 불러왔습니다.")

    vendor_summary = summarize_high_risk_by_vendor(
        df, top_n=top_n, severity_threshold=selected_severity
    )
    product_summary = summarize_high_risk_by_product(
        df, top_n=top_n, severity_threshold=selected_severity
    )
    cwe_summary = summarize_high_risk_by_cwe(
        df, top_n=top_n, severity_threshold=selected_severity
    )

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("벤더별 고위험 분포")
        st.plotly_chart(
            build_high_risk_vendor_chart(vendor_summary),
            use_container_width=True,
        )
        st.dataframe(vendor_summary, use_container_width=True)
    with c2:
        st.subheader("제품별 고위험 분포")
        st.plotly_chart(
            build_high_risk_product_chart(product_summary),
            use_container_width=True,
        )
        st.dataframe(product_summary, use_container_width=True)

    st.subheader("CWE별 고위험 유형")
    st.plotly_chart(
        build_high_risk_cwe_chart(cwe_summary),
        use_container_width=True,
    )
    st.dataframe(cwe_summary, use_container_width=True)

    st.info("이 스크립트는 `streamlit run script/high_risk_dashboard.py` 로 실행할 수 있습니다.")


if __name__ == "__main__":
    main()

# streamlit run script/high_risk_test_dashboard.py 으로 실행