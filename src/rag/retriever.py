from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from ..config import INDEX_DIR

try:
    import faiss  # type: ignore
except ImportError:  # pragma: no cover
    faiss = None


@dataclass
class RetrievalResult:
    text: str
    score: float
    metadata: dict


class RagRetriever:
    """
    FAISS + LangChain compatible retriever skeleton.

    TODO: plug this into a LangChain RetrievalQA chain once prompts/model access are available.
    """

    def __init__(self, index_path: Path | None = None) -> None:
        self.index_path = Path(index_path or (INDEX_DIR / "faiss.index"))
        self.index = None

    def load(self) -> None:
        if faiss is None:
            raise ImportError("faiss is required to load the vector index")
        if not self.index_path.exists():
            raise FileNotFoundError(self.index_path)
        # TODO: store accompanying metadata (JSON/SQLite). For now we only load the FAISS structure.
        self.index = faiss.read_index(str(self.index_path))

    def ask(self, question: str, top_k: int = 5, citations: bool = True) -> str:
        """
        Run the query against the FAISS index and format an answer string.

        TODO: integrate LLM call (LangChain RetrievalQA) and return structured results.
        """
        if self.index is None:
            raise RuntimeError("Retriever index is not loaded. Call load() before ask().")
        # Placeholder: return canned message until LLM chain is wired.
        return f"[TODO] Answer for '{question}' (top_k={top_k}, citations={citations})"

    def similarity_search(self, embedding: Sequence[float], top_k: int = 5) -> list[RetrievalResult]:
        """
        TODO: implement semantic search using the loaded FAISS index and stored metadata.
        """
        raise NotImplementedError("FAISS similarity search is not implemented yet")
