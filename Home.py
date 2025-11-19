from __future__ import annotations

from pathlib import Path
import sys

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.app import common  # noqa: E402

st.set_page_config(page_title="CVE/CWE Insight Explorer", layout="wide")
st.title("CVE / CWE 인사이트 허브")

st.sidebar.success("상단의 Streamlit 페이지 네비게이터에서 원하는 인사이트를 선택하세요.")

dataset_root = st.text_input(
    "데이터셋 디렉터리",
    value=common.get_dataset_root(),
    help="처리된 JSON 샤드가 들어 있는 폴더 경로를 지정합니다.",
)

available_years = common.discover_available_years(dataset_root)
if not available_years:
    st.error("처리된 데이터셋을 찾을 수 없습니다. build_dataset.py를 먼저 실행하거나 경로를 확인하세요.")
    st.stop()

selected_years = st.multiselect(
    "연도 선택",
    options=available_years,
    default=[year for year in available_years if year == 2025] or available_years,
    help="왼쪽 페이지 메뉴에서 선택한 모든 인사이트에 동일한 연도 필터가 적용됩니다.",
)

if not selected_years:
    st.warning("최소 한 개 이상의 연도를 선택해야 합니다.")
    st.stop()

common.set_dataset_context(dataset_root, selected_years)
df = common.ensure_dataframe()
if df is None:
    st.error("데이터셋을 로드하지 못했습니다. 경로/연도 설정을 확인하세요.")
    st.stop()

st.success(f"{len(df):,} 건의 레코드를 로드했습니다.")
st.metric("선택 연도", " ,".join(str(year) for year in selected_years))
st.write(
    "좌측 사이드바의 *Pages* 섹션에서 각 인사이트 페이지를 선택하면 동일한 필터와 RAG 설정이 적용된 상태로 분석을 진행할 수 있습니다."
)

common.ensure_retriever()
