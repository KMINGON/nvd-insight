# download_data.py
import gzip
import tarfile
import zipfile
import shutil
from pathlib import Path

import requests

# -------------------------------------------------------------------
# 설정 (필요하면 여기만 수정)
# -------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
RAW_CVE_DIR = RAW_DIR / "cve"
RAW_CPE_DIR = RAW_DIR / "cpe"
RAW_CWE_DIR = RAW_DIR / "cwe"

# CVE: 기본 연도 범위 (원하면 이 리스트만 수정)
CVE_YEARS_DEFAULT = list(range(2020, 2026))  # 2020, 2021, ..., 2025

# CVE Feeds (.gz)
CVE_BASE_URL_GZ = (
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
)

# CPE Dictionary (tar.gz)
CPE_DICT_TAR_URL = (
    "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"
)

# CWE (zip)
CWE_ZIP_URL = (
    "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
)
CWE_TARGET_XML_NAME = "cwec_v4.18.xml"


# -------------------------------------------------------------------
# 공통 유틸
# -------------------------------------------------------------------

def ensure_dirs() -> None:
    RAW_CVE_DIR.mkdir(parents=True, exist_ok=True)
    RAW_CPE_DIR.mkdir(parents=True, exist_ok=True)
    RAW_CWE_DIR.mkdir(parents=True, exist_ok=True)


def download_stream(url: str, dest_path: Path, chunk_size: int = 1024 * 1024) -> None:
    """HTTP 스트리밍 다운로드 (이미 파일 있으면 스킵)."""
    if dest_path.exists():
        print(f"[SKIP] already exists: {dest_path}")
        return

    print(f"[DL] {url} -> {dest_path}")
    with requests.get(url, stream=True, timeout=60) as resp:
        resp.raise_for_status()
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)


# -------------------------------------------------------------------
# 1) CVE: 연도별 .gz → JSON
# -------------------------------------------------------------------

def download_cve(years=None) -> None:
    """CVE JSON 2.0 피드를 연도별로 다운 + gzip 해제."""
    ensure_dirs()
    if years is None:
        years = CVE_YEARS_DEFAULT

    for year in years:
        url = CVE_BASE_URL_GZ.format(year=year)
        gz_path = RAW_CVE_DIR / f"nvdcve-2.0-{year}.json.gz"
        json_path = RAW_CVE_DIR / f"nvdcve-2.0-{year}.json"

        # 이미 해제된 json이 있으면 스킵
        if json_path.exists():
            print(f"[CVE] JSON already exists, skip: {json_path}")
            continue

        # .gz 다운로드
        download_stream(url, gz_path)

        # gzip 해제
        print(f"[CVE] Decompressing {gz_path} -> {json_path}")
        with gzip.open(gz_path, "rb") as gz_f, open(json_path, "wb") as out_f:
            shutil.copyfileobj(gz_f, out_f)


# -------------------------------------------------------------------
# 2) tar.gz 내부 chunk JSON 추출 (CPE Dict 공용)
# -------------------------------------------------------------------

def _extract_tar_chunks(
    tar_path: Path,
    dest_dir: Path,
    expected_dir_prefix: str,
) -> None:
    """
    tar.gz 내부에서 expected_dir_prefix/ 아래 있는 파일들을 dest_dir로 추출.

    예: expected_dir_prefix="nvdcpe-2.0-chunks"
    """
    print(f"[TAR] Extracting chunks from {tar_path}")
    dest_dir.mkdir(parents=True, exist_ok=True)

    with tarfile.open(tar_path, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            # 디렉터리 프리픽스 체크
            if not member.name.startswith(expected_dir_prefix):
                continue

            # 멤버 실제 파일명만 사용
            fname = Path(member.name).name
            out_path = dest_dir / fname

            if out_path.exists():
                print(f"[SKIP] already exists: {out_path}")
                continue

            # 추출
            print(f"[EXTRACT] {member.name} -> {out_path}")
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, open(out_path, "wb") as f:
                shutil.copyfileobj(src, f)


# -------------------------------------------------------------------
# 3) CPE Dictionary (tar.gz → chunks)
# -------------------------------------------------------------------

def download_cpe_dictionary() -> None:
    """CPE Dictionary 2.0 tar.gz를 받아 chunks를 data/raw/cpe에 저장."""
    ensure_dirs()

    tar_path = RAW_CPE_DIR / "nvdcpe-2.0.tar.gz"
    download_stream(CPE_DICT_TAR_URL, tar_path)

    _extract_tar_chunks(
        tar_path=tar_path,
        dest_dir=RAW_CPE_DIR,
        expected_dir_prefix="nvdcpe-2.0-chunks",
    )


# -------------------------------------------------------------------
# 4) CWE (zip → cwec_v4.18.xml)
# -------------------------------------------------------------------

def download_cwe() -> None:
    """CWE zip을 받아 cwec_v4.18.xml을 data/raw/cwe에 저장."""
    ensure_dirs()

    zip_path = RAW_CWE_DIR / "cwec_v4.18.xml.zip"
    xml_path = RAW_CWE_DIR / CWE_TARGET_XML_NAME

    if xml_path.exists():
        print(f"[CWE] XML already exists, skip: {xml_path}")
        return

    download_stream(CWE_ZIP_URL, zip_path)

    print(f"[CWE] Extracting {CWE_TARGET_XML_NAME} from {zip_path}")
    with zipfile.ZipFile(zip_path, "r") as zf:
        # 압축 안에 동일 이름이 있다고 가정
        with zf.open(CWE_TARGET_XML_NAME, "r") as src, open(xml_path, "wb") as dst:
            shutil.copyfileobj(src, dst)


# -------------------------------------------------------------------
# 6) 전체 실행 진입점
# -------------------------------------------------------------------

def main():
    """
    전체 다운로드:
      - CVE (기본 2020~2025)
      - CPE Dictionary
      - CWE
    필요하면 main()을 여러 번 돌려도, 이미 있는 파일은 스킵된다.
    """
    ensure_dirs()

    print("=== Download CVE Feeds ===")
    download_cve()

    print("=== Download CPE Dictionary ===")
    download_cpe_dictionary()

    print("=== Download CWE ===")
    download_cwe()


if __name__ == "__main__":
    main()
