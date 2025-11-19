from __future__ import annotations

import re
from typing import Optional, Sequence, Tuple

import pandas as pd
import streamlit as st

from ..analytics import iter_dataset_files, load_processed_dataframe
from ..config import PROCESSED_DATASET_DIR
from ..rag import RagRetriever

YEAR_PATTERN = re.compile(r"(\d{4})")
DEFAULT_DATASET_ROOT = str(PROCESSED_DATASET_DIR)
SESSION_DATASET_PATH = "dataset_root"
SESSION_SELECTED_YEARS = "selected_years"
SESSION_DATAFRAME = "filtered_dataframe"
SESSION_RETRIEVER = "rag_retriever"


def discover_available_years(dataset_path: str | None) -> list[int]:
    """처리된 데이터셋 경로에서 사용 가능한 연도를 추출한다."""
    years: set[int] = set()
    if not dataset_path:
        dataset_path = DEFAULT_DATASET_ROOT
    try:
        for path in iter_dataset_files(dataset_path):
            match = YEAR_PATTERN.search(path.stem)
            if match:
                years.add(int(match.group(1)))
    except FileNotFoundError:
        return []
    return sorted(years)


@st.cache_data(show_spinner=False)
def _load_filtered_dataframe(dataset_path: str, years: Tuple[int, ...]) -> pd.DataFrame:
    year_seq: Optional[Sequence[int]] = list(years)
    return load_processed_dataframe(dataset_path=dataset_path, years=year_seq)


def set_dataset_context(dataset_path: str, years: Sequence[int]) -> None:
    """세션에 데이터셋 경로와 선택 연도를 저장한다."""
    st.session_state[SESSION_DATASET_PATH] = dataset_path
    st.session_state[SESSION_SELECTED_YEARS] = tuple(sorted(int(year) for year in years))
    # 캐시된 DF를 다시 로드하도록 기존 값을 제거한다.
    st.session_state.pop(SESSION_DATAFRAME, None)


def get_selected_years() -> Tuple[int, ...]:
    return tuple(st.session_state.get(SESSION_SELECTED_YEARS, ()))


def ensure_dataframe() -> Optional[pd.DataFrame]:
    dataset_path = st.session_state.get(SESSION_DATASET_PATH, DEFAULT_DATASET_ROOT)
    years = get_selected_years()
    if not dataset_path or not years:
        return None
    df = _load_filtered_dataframe(dataset_path, years)
    st.session_state[SESSION_DATAFRAME] = df
    return df


def get_dataframe() -> Optional[pd.DataFrame]:
    df = st.session_state.get(SESSION_DATAFRAME)
    if df is not None:
        return df
    return ensure_dataframe()


def ensure_retriever() -> Optional[RagRetriever]:
    retriever: Optional[RagRetriever] = st.session_state.get(SESSION_RETRIEVER)
    if retriever is not None:
        return retriever
    try:
        retriever = RagRetriever()
        retriever.load()
    except Exception as exc:  # pragma: no cover - UI 피드백 전용
        st.sidebar.warning(f"RAG 검색기를 불러오지 못했습니다: {exc}")
        return None
    st.session_state[SESSION_RETRIEVER] = retriever
    return retriever


def build_session_key(base: str, years: Tuple[int, ...], suffix: str | None = None) -> str:
    year_part = "-".join(str(year) for year in years) if years else "all"
    key = f"{base}_{year_part}"
    if suffix:
        key = f"{key}_{suffix}"
    return key


def get_dataset_root() -> str:
    return st.session_state.get(SESSION_DATASET_PATH, DEFAULT_DATASET_ROOT)
