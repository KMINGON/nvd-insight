from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from ..config import DEFAULT_DESCRIPTION_LANG

LANG_FALLBACK = ("en", "es")


def load_cve_records(
    cve_dir: Path, languages: Sequence[str] | None = None
) -> List[dict]:
    """
    Load CVE feed files and project to the columns defined in docs/require_columns.md.
    """
    cve_dir = Path(cve_dir)
    lang_pref = languages or (DEFAULT_DESCRIPTION_LANG,)
    records: List[dict] = []
    for feed_path in sorted(cve_dir.glob("*.json")):
        with feed_path.open("r", encoding="utf-8") as fh:
            feed = json.load(fh)
        for entry in feed.get("vulnerabilities", []):
            cve = entry.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue
            record = {
                "cveId": cve_id,
                "published": cve.get("published"),
                "lastModified": cve.get("lastModified"),
                "description": _extract_description(cve.get("descriptions", []), lang_pref),
                "metrics": cve.get("metrics", {}),
                "cisaExploitAdd": cve.get("cisaExploitAdd"),
                "configurations": cve.get("configurations", []),
                "weaknesses": _extract_cwe_ids(cve.get("weaknesses", [])),
            }
            records.append(record)
    return records


def load_cpe_dictionary(cpe_dir: Path) -> Dict[str, dict]:
    """
    Build a dictionary keyed by CPE 2.3 URI with associated metadata.
    """
    cpe_dir = Path(cpe_dir)
    dictionary: Dict[str, dict] = {}
    for chunk_path in sorted(cpe_dir.glob("*.json")):
        with chunk_path.open("r", encoding="utf-8") as fh:
            chunk = json.load(fh)
        for product in chunk.get("products", []):
            cpe_obj = product.get("cpe") or {}
            cpe_name = cpe_obj.get("cpeName")
            if not cpe_name:
                continue
            dictionary[cpe_name] = cpe_obj
    return dictionary


def load_cwe_catalog(cwe_file: Path) -> Dict[str, dict]:
    """
    Parse the CWE XML catalog and retain only the required descriptive fields.
    """
    cwe_file = Path(cwe_file)
    tree = ET.parse(cwe_file)
    root = tree.getroot()
    ns = {"cwe": "http://cwe.mitre.org/cwe-7"}
    catalog: Dict[str, dict] = {}
    for weakness in root.findall(".//cwe:Weaknesses/cwe:Weakness", ns):
        cwe_numeric = weakness.get("ID")
        if not cwe_numeric:
            continue
        cwe_id = f"CWE-{cwe_numeric}"
        name = weakness.get("Name")
        description = _strip_text(weakness.findtext("cwe:Description", default="", namespaces=ns))
        extended = _strip_text(
            weakness.findtext("cwe:Extended_Description", default="", namespaces=ns)
        )
        background = _collect_background_details(weakness.findall("cwe:Background_Details/cwe:Background_Detail", ns))
        catalog[cwe_id] = {
            "name": name or description,
            "description": description,
            "extended_description": extended or description,
            "background_details": background,
        }
    return catalog


def _extract_description(descriptions: Iterable[dict], languages: Sequence[str]) -> str | None:
    for lang in tuple(languages) + LANG_FALLBACK:
        for item in descriptions or []:
            if item.get("lang") == lang and item.get("value"):
                return item["value"]
    if descriptions:
        fallback = next((item for item in descriptions if item.get("value")), None)
        if fallback:
            return fallback.get("value")
    return None


def _extract_cwe_ids(weaknesses: Iterable[dict]) -> List[str]:
    ids: List[str] = []
    seen = set()
    for weakness in weaknesses or []:
        for desc in weakness.get("description", []):
            cwe_id = desc.get("value")
            if not cwe_id or cwe_id in seen:
                continue
            seen.add(cwe_id)
            ids.append(cwe_id)
    return ids


def _collect_background_details(elements: Iterable[ET.Element]) -> str | None:
    texts = [_strip_text(elem.text) for elem in elements if _strip_text(elem.text)]
    return "\n".join(texts) if texts else None


def _strip_text(value: str | None) -> str | None:
    return value.strip() if value else None


if __name__ == "__main__":
    from .. import config

    cves = load_cve_records(config.RAW_CVE_DIR)
    cpe_dict = load_cpe_dictionary(config.RAW_CPE_DIR)
    cwe_catalog = load_cwe_catalog(config.RAW_CWE_FILE)
    print(f"CVE records: {len(cves)}")
    print(f"CPE entries: {len(cpe_dict)}")
    print(f"CWE entries: {len(cwe_catalog)}")
