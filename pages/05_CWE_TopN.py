from __future__ import annotations

from pathlib import Path
import sys

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.app import common  # noqa: E402
from src.app.pages import render_cwe_page  # noqa: E402

st.title("CWE Top-N 인사이트")

df = common.get_dataframe()
years = common.get_selected_years()
if df is None or not years:
    st.info("먼저 Home 페이지에서 데이터 경로와 연도를 선택하세요.")
    st.stop()

retriever = common.ensure_retriever()
render_cwe_page(df, years, retriever)
