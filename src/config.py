from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


def _env(key: str, default: str | None = None, *, strip: bool = True) -> str | None:
    """환경 변수를 가져오되 공백/빈 문자열이면 기본값을 반환한다."""
    value = os.getenv(key)
    if value is None:
        return default
    if strip:
        value = value.strip()
    return value or default


# Base paths ---------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOTENV_PATH = PROJECT_ROOT / ".env"
load_dotenv(dotenv_path=DOTENV_PATH if DOTENV_PATH.exists() else None)
DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
INDEX_DIR = DATA_DIR / "index"
FAISS_INDEX_DIR = Path(_env("FAISS_INDEX_DIR", str(INDEX_DIR / "faiss")))

# Raw data sources ---------------------------------------------------------
RAW_CVE_DIR = RAW_DIR / "cve"
RAW_CPE_DIR = RAW_DIR / "cpe"
RAW_CWE_FILE = RAW_DIR / "cwe" / "cwec_v4.18.xml"

# Processed artifacts ------------------------------------------------------
PROCESSED_DATASET_DIR = PROCESSED_DIR / "cve_cwe_by_year"
PROCESSED_DATASET_PATTERN = "cve_cwe_dataset_{year}.json"

# Reports ------------------------------------------------------------------
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_FIGURES_DIR = REPORTS_DIR / "figures"
REPORTS_TEXT_DIR = REPORTS_DIR / "text"

# General configuration ----------------------------------------------------
DEFAULT_DESCRIPTION_LANG = "en"
DEFAULT_TOP_K = 5
EMBEDDING_BACKEND = (_env("EMBEDDING_BACKEND", "local") or "local").lower()
LOCAL_EMBEDDING_MODEL = _env("LOCAL_EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
OPENAI_EMBEDDING_MODEL = _env("OPENAI_EMBEDDING_MODEL", "text-embedding-3-large")
EMBEDDING_MODEL_OVERRIDE = _env("EMBEDDING_MODEL")
DEFAULT_EMBEDDING_MODEL = EMBEDDING_MODEL_OVERRIDE or (
    OPENAI_EMBEDDING_MODEL if EMBEDDING_BACKEND == "openai" else LOCAL_EMBEDDING_MODEL
)
DEFAULT_CHAT_MODEL = _env("CHAT_COMPLETION_MODEL", "gpt-4o-mini")
OPENAI_API_KEY = _env("OPENAI_API_KEY")
