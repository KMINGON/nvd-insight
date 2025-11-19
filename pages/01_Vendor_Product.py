from __future__ import annotations

from pathlib import Path
import sys

import streamlit as st

# ---------------------------------------------------------
# 프로젝트 root 경로 추가
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.app import common  # noqa: E402
from src.app.pages import render_vendor_product_page  # noqa: E402

# ---------------------------------------------------------
# 페이지 타이틀 + 초보자 안내
# ---------------------------------------------------------
st.title("벤더 / 제품 Top-N 취약점 인사이트")
st.caption(
    "이 페이지에서는 어떤 회사(Vendor)와 제품(Product)에서 취약점이 많이 발견되는지 쉽게 분석할 수 있어요!\n"
    "초보자도 이해하기 쉽도록 그래프와 표로 정리해 보여드립니다"
)

# ---------------------------------------------------------
# 데이터 로딩
# ---------------------------------------------------------
df = common.get_dataframe()
years = common.get_selected_years()

if df is None or not years:
    st.info("먼저 Home 페이지에서 데이터 경로와 분석할 연도를 선택해주세요!")
    st.stop()

retriever = common.ensure_retriever()

# ---------------------------------------------------------
# 실제 분석 페이지 렌더링
# ---------------------------------------------------------
render_vendor_product_page(df, years, retriever)
