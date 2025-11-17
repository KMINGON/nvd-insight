from __future__ import annotations

from pathlib import Path

# Base paths ---------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
INDEX_DIR = DATA_DIR / "index"

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
