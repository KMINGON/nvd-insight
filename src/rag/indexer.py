from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence, Tuple

from .. import config

try:
    from langchain_core.documents import Document
    from langchain_community.vectorstores import FAISS
    from langchain_openai import OpenAIEmbeddings
    from langchain_community.embeddings import HuggingFaceEmbeddings
except ImportError:  # pragma: no cover
    Document = None
    OpenAIEmbeddings = None
    FAISS = None
    HuggingFaceEmbeddings = None

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None


@dataclass
class IndexRecord:
    page_content: str
    metadata: dict


class VectorIndexer:
    """
    FAISS 인덱스를 구축하기 위한 경량 래퍼.

    TODO: 구성/CLI 인자를 통해 OpenAI, 로컬 등 다양한 임베딩 백엔드를 선택할 수 있도록 확장한다.
    """

    def __init__(
        self,
        dataset_path: Path | None = None,
        index_dir: Path | None = None,
        embedding_model: str | None = None,
        embedding_backend: str | None = None,
    ) -> None:
        self.dataset_path = Path(dataset_path or config.PROCESSED_DATASET_DIR)
        self.index_dir = Path(index_dir or config.FAISS_INDEX_DIR)
        self.index_name = "cve_cwe_index"
        self.embedding_model = embedding_model or config.DEFAULT_EMBEDDING_MODEL
        self.embedding_backend = (embedding_backend or config.EMBEDDING_BACKEND).lower()

    def load_documents(self) -> List[IndexRecord]:
        """TODO: 처리된 데이터를 스트리밍하면서 의미 단위별 청크로 분할해 메모리 사용량을 줄인다."""
        records: List[IndexRecord] = []
        for json_file in sorted(self.dataset_path.glob("*.json")):
            with json_file.open("r", encoding="utf-8") as fh:
                try:
                    rows = json.load(fh)
                except json.JSONDecodeError:  # pragma: no cover - invalid input guard
                    continue
            for row in rows:
                metadata = self._build_metadata(row)
                page_content = json.dumps(row, ensure_ascii=False)
                records.append(IndexRecord(page_content=page_content, metadata=metadata))
        return records

    def build(
        self,
        docs: Sequence[IndexRecord] | None = None,
        *,
        batch_size: int = 128,
        show_progress: bool = False,
    ) -> Path:
        """
        문서를 임베딩해 FAISS 인덱스를 구성하고 디스크에 저장한다.

        TODO: 증분 업데이트 및 메타데이터 저장을 지원해 재색인을 최소화한다.
        """
        if docs is None:
            docs = self.load_documents()
        if not docs:
            raise ValueError("No documents supplied for indexing")
        if FAISS is None:
            raise ImportError("langchain FAISS dependency is missing")
        if Document is None:
            raise ImportError("langchain Document type is required")
        self.index_dir.mkdir(parents=True, exist_ok=True)
        embeddings = self._resolve_embeddings()
        total_batches = max(1, math.ceil(len(docs) / max(batch_size, 1)))
        progress = None
        if show_progress and tqdm is not None:
            progress = tqdm(total=total_batches, desc="Embedding batches", unit="batch")

        vector_store = None
        for start in range(0, len(docs), max(batch_size, 1)):
            chunk = docs[start : start + batch_size]
            documents = [Document(page_content=rec.page_content, metadata=rec.metadata) for rec in chunk]
            if vector_store is None:
                # TODO: JSON 문자열을 그대로 임베딩하기 전에 청크/오버랩 전략을 정의한다.
                vector_store = FAISS.from_documents(documents, embeddings)
            else:
                vector_store.add_documents(documents)
            if progress:
                progress.update(1)

        if progress:
            progress.close()
        if vector_store is None:
            raise RuntimeError("Vector store was not initialized; no documents were processed.")
        index_path = self.index_dir / self.index_name
        vector_store.save_local(folder_path=str(index_path))
        return index_path

    def _build_metadata(self, row: dict) -> dict:
        """
        정규화된 CVE 레코드에서 검색 가능한 메타데이터 사전을 생성한다.

        TODO: 향후 벤더/제품 기준 필터를 추가할 때 필요한 지표도 포함한다.
        """
        year = self._extract_year(row.get("published") or row.get("lastModified"))
        vendors, products = self._extract_cpe_entities(row.get("cpes"))
        cwes = self._extract_cwe_ids(row.get("cwes"))
        severity, score = self._extract_cvss_summary(row.get("metrics"))
        metadata = {
            "cveId": row.get("cveId"),
            "year": year,
            "type": "cve_record",
            "vendors": vendors or None,
            "products": products or None,
            "cwes": cwes or None,
            "severity": severity,
            "cvssScore": score,
        }
        return {k: v for k, v in metadata.items() if v not in (None, [], "", set())}

    @staticmethod
    def _extract_year(date_str: str | None) -> int | None:
        if not date_str:
            return None
        year_part = date_str[:4]
        return int(year_part) if year_part.isdigit() else None

    @staticmethod
    def _extract_cpe_entities(cpe_list) -> Tuple[List[str], List[str]]:
        vendors: set[str] = set()
        products: set[str] = set()
        if not isinstance(cpe_list, list):
            return ([], [])
        for entry in cpe_list:
            if not isinstance(entry, dict):
                continue
            criteria = entry.get("criteria") or entry.get("cpeName")
            vendor, product = VectorIndexer._parse_cpe(criteria)
            if vendor:
                vendors.add(vendor)
            if product:
                products.add(product)
        return (sorted(vendors), sorted(products))

    @staticmethod
    def _parse_cpe(criteria: str | None) -> Tuple[str | None, str | None]:
        if not criteria or not isinstance(criteria, str):
            return (None, None)
        parts = criteria.split(":")
        if len(parts) < 6:
            return (None, None)
        vendor = parts[3] or None
        product = parts[4] or None
        return (vendor, product)

    @staticmethod
    def _extract_cwe_ids(cwe_list) -> List[str]:
        if not isinstance(cwe_list, list):
            return []
        values = {item.get("cweId") for item in cwe_list if isinstance(item, dict) and item.get("cweId")}
        return sorted(values)

    @staticmethod
    def _extract_cvss_summary(metrics: dict | None) -> Tuple[str | None, float | None]:
        if not isinstance(metrics, dict):
            return (None, None)
        metric_keys = [
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ]
        for key in metric_keys:
            entries = metrics.get(key)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                cvss_data = entry.get("cvssData") or {}
                severity = (cvss_data.get("baseSeverity") or entry.get("baseSeverity") or "").upper()
                score = cvss_data.get("baseScore") or entry.get("baseScore")
                if severity or score:
                    try:
                        score_value = float(score) if score is not None else None
                    except (TypeError, ValueError):
                        score_value = None
                    return (severity or None, score_value)
        return (None, None)

    def _resolve_embeddings(self):
        model_name = self.embedding_model or config.DEFAULT_EMBEDDING_MODEL
        backend = (self.embedding_backend or "local").lower()
        if backend == "openai":
            if OpenAIEmbeddings is None:
                raise ImportError("LangChain OpenAIEmbeddings is unavailable")
            if not config.OPENAI_API_KEY:
                raise EnvironmentError("OPENAI_API_KEY is not configured")
            return OpenAIEmbeddings(model=model_name, openai_api_key=config.OPENAI_API_KEY)
        if HuggingFaceEmbeddings is None:
            raise ImportError("HuggingFaceEmbeddings unavailable; install sentence-transformers.")
        return HuggingFaceEmbeddings(model_name=model_name)
