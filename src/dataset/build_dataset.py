from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List

from .. import config
from .load_raw import load_cpe_dictionary, load_cve_records, load_cwe_catalog


def build_processed_dataset(
    cve_dir: Path | None = None,
    cpe_dir: Path | None = None,
    cwe_file: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Path]:
    """
    Load raw feeds and emit the normalized dataset described in docs/data_schema_for_analysis.md.
    결과는 연도별 JSON으로 `data/processed/cve_cwe_by_year/` 하위에 저장한다.
    """
    cve_dir = Path(cve_dir or config.RAW_CVE_DIR)
    cpe_dir = Path(cpe_dir or config.RAW_CPE_DIR)
    cwe_file = Path(cwe_file or config.RAW_CWE_FILE)
    output_dir = Path(output_dir or config.PROCESSED_DATASET_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    cve_records = load_cve_records(cve_dir)
    cpe_dict = load_cpe_dictionary(cpe_dir)
    cwe_catalog = load_cwe_catalog(cwe_file)

    buckets: dict[str, List[dict]] = defaultdict(list)
    for record in cve_records:
        enriched = {
            "cveId": record.get("cveId"),
            "published": record.get("published"),
            "lastModified": record.get("lastModified"),
            "description": record.get("description"),
            "metrics": record.get("metrics", {}),
            "cpes": _build_cpe_list(record.get("configurations", []), cpe_dict),
            "cwes": _build_cwe_list(record.get("weaknesses", []), cwe_catalog),
        }
        cisa_date = record.get("cisaExploitAdd")
        if cisa_date:
            enriched["cisaExploitAdd"] = cisa_date
        year_bucket = _extract_year(record.get("published") or record.get("lastModified"))
        bucket_key = str(year_bucket) if year_bucket is not None else "unknown"
        buckets[bucket_key].append(enriched)

    manifest: dict[str, Path] = {}
    for year_key, entries in sorted(buckets.items(), key=lambda item: item[0]):
        filename = config.PROCESSED_DATASET_PATTERN.format(year=year_key)
        output_path = output_dir / filename
        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(entries, fh, ensure_ascii=False)
        manifest[year_key] = output_path
    return manifest


def _build_cpe_list(configurations: Iterable[dict], cpe_dict: Dict[str, dict]) -> List[dict]:
    matches: List[dict] = []
    for configuration in configurations or []:
        nodes = configuration.get("nodes", [])
        matches.extend(_collect_cpe_matches(nodes, cpe_dict))
    return matches


def _collect_cpe_matches(nodes: Iterable[dict], cpe_dict: Dict[str, dict]) -> List[dict]:
    collected: List[dict] = []
    for node in nodes or []:
        match_entries = node.get("cpeMatch") or node.get("cpe_match") or []
        for match in match_entries:
            uri = (
                match.get("cpeName")
                or match.get("cpe23Uri")
                or match.get("criteria")
            )
            entry = {
                "cpeName": uri,
                "vulnerable": bool(match.get("vulnerable")),
                "criteria": match.get("criteria"),
                "matchCriteriaId": match.get("matchCriteriaId"),
                "cpeMeta": cpe_dict.get(uri),
            }
            collected.append(entry)
        child_nodes = node.get("children") or []
        if child_nodes:
            collected.extend(_collect_cpe_matches(child_nodes, cpe_dict))
    return collected


def _build_cwe_list(weaknesses: Iterable[str], cwe_catalog: Dict[str, dict]) -> List[dict]:
    enriched: List[dict] = []
    for cwe_id in weaknesses or []:
        meta = cwe_catalog.get(cwe_id)
        enriched.append(
            {
                "cweId": cwe_id,
                "cweDescription": (meta or {}).get("name"),
                "cweExtendedDescription": (meta or {}).get("extended_description"),
                "cweBackgroundDetails": (meta or {}).get("background_details"),
            }
        )
    return enriched


def _extract_year(date_str: str | None) -> int | None:
    """
    ISO8601 형태의 문자열에서 연도(정수)를 파싱한다.
    """
    if not date_str:
        return None
    year_part = date_str[:4]
    if year_part.isdigit():
        return int(year_part)
    return None


if __name__ == "__main__":
    build_processed_dataset()
