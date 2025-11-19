from __future__ import annotations

from pathlib import Path
import sys

import streamlit as st

# ---------------------------------------------------------
# 프로젝트 루트 경로 추가 (초보자: "이 코드가 내부 모듈을 찾도록 도와줍니다!")
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.app import common  # noqa: E402
from src.app.pages import render_published_trend_page  # noqa: E402

# ---------------------------------------------------------
# 초보자용 페이지 소개
# ---------------------------------------------------------
st.title("Published Trend 시계열 인사이트")
st.caption(
    "이 페이지에서는 CVE가 언제 공개되었는지 연·월 단위 흐름을 쉽게 분석할 수 있어요!\n"
    "보안 데이터를 처음 접하는 분도 이해할 수 있게 설명과 함께 제공됩니다"
)

# ---------------------------------------------------------
# 데이터 준비 단계
# ---------------------------------------------------------
df = common.get_dataframe()
years = common.get_selected_years()

if df is None or not years:
    st.info("먼저 Home 페이지에서 데이터 경로와 연도를 선택해야 분석을 시작할 수 있어요!")
    st.stop()

retriever = common.ensure_retriever()

# ---------------------------------------------------------
# 메인 분석 페이지 렌더링 (별도 파일)
# ---------------------------------------------------------
render_published_trend_page(df, years, retriever)
