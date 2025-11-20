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
class IndexRecord:  # 인덱싱할 단일 문서 레코드
    page_content: str
    metadata: dict


class VectorIndexer:
    """처리된 데이터셋 샤드로부터 FAISS 인덱스를 구성하는 경량 래퍼.

    정규화된 CVE/CWE 행을 읽어 메타데이터를 추출하고 청크를 임베딩하여
    Streamlit UI가 RAG 검색을 수행할 수 있도록 FAISS 인덱스를 저장한다.
    """

    def __init__(
        self,
        dataset_path: Path | None = None,
        index_dir: Path | None = None,
        embedding_model: str | None = None,
        embedding_backend: str | None = None,
    ) -> None:
        # config 값을 기본값으로 삼되 인자로 전달되면 그대로 교체한다.
        self.dataset_path = Path(dataset_path or config.PROCESSED_DATASET_DIR)
        self.index_dir = Path(index_dir or config.FAISS_INDEX_DIR)
        self.index_name = "cve_cwe_index"
        self.embedding_model = embedding_model or config.DEFAULT_EMBEDDING_MODEL
        self.embedding_backend = (embedding_backend or config.EMBEDDING_BACKEND).lower()

    def load_documents(self) -> List[IndexRecord]:
        """처리된 JSON 파일을 순회해 IndexRecord 리스트로 변환한다.

        반환값:
            List[IndexRecord]: 직렬화된 JSON 텍스트와 메타데이터를 포함한 레코드들.

        참고:
            현재는 단순화를 위해 전체 데이터를 불러오며, 향후에는 스트리밍이나
            청킹으로 메모리 사용량을 줄일 수 있다.
        """
        records: List[IndexRecord] = []
        # 연도별 샤드 파일을 사전순으로 정렬해 안정적인 처리 순서를 유지한다.
        for json_file in sorted(self.dataset_path.glob("*.json")):
            with json_file.open("r", encoding="utf-8") as fh:
                try:
                    rows = json.load(fh)
                except json.JSONDecodeError:
                    continue
            for row in rows:
                # 인덱싱 단위는 "행"이므로 각 행마다 메타데이터와 텍스트를 추출한다.
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
        """문서를 임베딩해 FAISS 인덱스를 만들고 디스크에 저장한다.

        매개변수:
            docs: 미리 로드한 레코드. 없으면 데이터셋 경로를 자체 스캔한다.
            batch_size: 임베딩 배치당 문서 수.
            show_progress: 가능하면 tqdm 진행률 표시 여부.

        반환값:
            Path: 저장된 FAISS 인덱스가 위치한 디렉터리.

        예외:
            ValueError: 전달된 문서가 없을 때.
            ImportError: LangChain/FAISS 의존성이 없을 때.
            RuntimeError: 벡터 스토어 생성에 실패했을 때.
        """
        if docs is None:
            docs = self.load_documents()
        if not docs:
            raise ValueError("No documents supplied for indexing")
        if FAISS is None:
            raise ImportError("langchain FAISS dependency is missing")
        if Document is None:
            raise ImportError("langchain Document type is required")
        # 인덱스가 저장될 디렉터리를 미리 만들어 경로 관련 에러를 방지한다.
        self.index_dir.mkdir(parents=True, exist_ok=True)
        embeddings = self._resolve_embeddings()
        total_batches = max(1, math.ceil(len(docs) / max(batch_size, 1)))
        progress = None
        if show_progress and tqdm is not None:
            progress = tqdm(total=total_batches, desc="Embedding batches", unit="batch")

        vector_store = None
        for start in range(0, len(docs), max(batch_size, 1)):
            chunk = docs[start : start + batch_size]
            # LangChain Document 객체는 page_content/metadata를 그대로 포함한다.
            documents = [Document(page_content=rec.page_content, metadata=rec.metadata) for rec in chunk]
            if vector_store is None:
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
        # save_local은 디렉터리 단위로 보존되므로 해당 경로를 그대로 반환한다.
        vector_store.save_local(folder_path=str(index_path))
        return index_path

    def _build_metadata(self, row: dict) -> dict:
        """정규화된 CVE 레코드에서 검색 가능한 메타데이터를 추출한다."""
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
        # None/빈 값은 검색 필터에서 의미가 없으므로 마지막에 모두 제거한다.
        return {k: v for k, v in metadata.items() if v not in (None, [], "", set())}

    @staticmethod
    def _extract_year(date_str: str | None) -> int | None:
        """ISO 형태의 타임스탬프에서 4자리 연도를 뽑아낸다."""
        if not date_str:
            return None
        year_part = date_str[:4]
        # 숫자로만 이뤄진 경우에만 정수로 변환해 반환한다.
        return int(year_part) if year_part.isdigit() else None

    @staticmethod
    def _extract_cpe_entities(cpe_list) -> Tuple[List[str], List[str]]:
        """NVD 형태의 CPE 목록에서 벤더/제품 식별자를 파싱한다."""
        vendors: set[str] = set()
        products: set[str] = set()
        if not isinstance(cpe_list, list):
            return ([], [])
        for entry in cpe_list:
            if not isinstance(entry, dict):
                continue
            criteria = entry.get("criteria") or entry.get("cpeName")
            # criteria 문자열을 파싱해 벤더/제품 문자열을 분리한다.
            vendor, product = VectorIndexer._parse_cpe(criteria)
            if vendor:
                vendors.add(vendor)
            if product:
                products.add(product)
        return (sorted(vendors), sorted(products))

    @staticmethod
    def _parse_cpe(criteria: str | None) -> Tuple[str | None, str | None]:
        """CPE URI를 분해해 벤더와 제품 구간을 반환한다."""
        if not criteria or not isinstance(criteria, str):
            return (None, None)
        parts = criteria.split(":")
        if len(parts) < 6:
            return (None, None)
        # CPE URI는 cpe:2.3:a:vendor:product:... 구조를 갖는다.
        vendor = parts[3] or None
        product = parts[4] or None
        return (vendor, product)

    @staticmethod
    def _extract_cwe_ids(cwe_list) -> List[str]:
        """복잡한 NVD CWE 필드에서 CWE ID만 수집한다."""
        if not isinstance(cwe_list, list):
            return []
        # set을 사용해 중복을 없앤 뒤 정렬된 리스트로 반환한다.
        values = {item.get("cweId") for item in cwe_list if isinstance(item, dict) and item.get("cweId")}
        return sorted(values)

    @staticmethod
    def _extract_cvss_summary(metrics: dict | None) -> Tuple[str | None, float | None]:
        """중첩된 CVSS 메트릭에서 대표 심각도/점수 쌍을 선택한다."""
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
                # CVSS v4/v3/v2 구조 모두 baseSeverity/baseScore 정보를 갖고 있으므로 우선 추출한다.
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
        """설정에 따라 OpenAI 또는 로컬 HuggingFace 임베딩을 반환한다."""
        model_name = self.embedding_model or config.DEFAULT_EMBEDDING_MODEL
        backend = (self.embedding_backend or "local").lower()
        if backend == "openai":
            if OpenAIEmbeddings is None:
                raise ImportError("LangChain OpenAIEmbeddings is unavailable")
            if not config.OPENAI_API_KEY:
                raise EnvironmentError("OPENAI_API_KEY is not configured")
            # OpenAI 백엔드는 API 키를 명시적으로 전달해야 한다.
            return OpenAIEmbeddings(model=model_name, openai_api_key=config.OPENAI_API_KEY)
        if HuggingFaceEmbeddings is None:
            raise ImportError("HuggingFaceEmbeddings unavailable; install sentence-transformers.")
        # 기본값은 로컬 sentence-transformers 모델을 사용하는 HuggingFace 백엔드다.
        return HuggingFaceEmbeddings(model_name=model_name)
