from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

from ..config import INDEX_DIR, PROCESSED_DATASET_DIR

try:
    import faiss  # type: ignore
except ImportError:  # pragma: no cover
    faiss = None

try:
    from langchain.embeddings import OpenAIEmbeddings
except ImportError:  # pragma: no cover
    OpenAIEmbeddings = None


@dataclass
class IndexRecord:
    page_content: str
    metadata: dict


class VectorIndexer:
    """
    Thin wrapper around FAISS for building document indexes.

    TODO: parameterize embedding providers (OpenAI, local, etc.) through config/CLI args.
    """

    def __init__(
        self,
        dataset_path: Path | None = None,
        index_dir: Path | None = None,
        embedding_model: str = "text-embedding-3-large",
    ) -> None:
        self.dataset_path = Path(dataset_path or PROCESSED_DATASET_DIR)
        self.index_dir = Path(index_dir or INDEX_DIR)
        self.embedding_model = embedding_model

    def load_documents(self) -> List[IndexRecord]:
        """
        TODO: stream processed dataset and split into semantically meaningful chunks.
        """
        # Placeholder implementation: return empty list until chunking rules are defined.
        return []

    def build(self, docs: Sequence[IndexRecord] | None = None) -> Path:
        """
        Construct the FAISS index and persist it to disk.

        TODO: add incremental update support and metadata persistence alongside the FAISS file.
        """
        if docs is None:
            docs = self.load_documents()
        if not docs:
            raise ValueError("No documents supplied for indexing")
        if faiss is None or OpenAIEmbeddings is None:
            raise ImportError("faiss and langchain embeddings must be installed to build the index")
        self.index_dir.mkdir(parents=True, exist_ok=True)
        # TODO: Embed docs, build IndexFlatIP (or similar), and serialize with faiss.write_index.
        raise NotImplementedError("Index build logic not implemented yet")
