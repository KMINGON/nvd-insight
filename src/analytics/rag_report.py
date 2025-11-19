from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from ..rag.retriever import RagRetriever
from ..config import REPORTS_TEXT_DIR


@dataclass
class RagReportInput:
    question: str
    top_k: int = 5
    citations: bool = True


def summarize_with_rag(
    retriever: RagRetriever,
    prompts: Sequence[RagReportInput],
    output_path: Optional[Path] = None,
) -> Path:
    """
    Generate a text report by running the provided prompts through the RAG retriever.

    TODO: move summarization prompts into a config file once prompt engineering stabilizes.
    """
    if not getattr(retriever, "is_loaded", False):
        retriever.load()

    output_path = Path(output_path or (REPORTS_TEXT_DIR / "rag_report.txt"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines: List[str] = []
    for prompt in prompts:
        answer = retriever.ask(prompt.question, top_k=prompt.top_k, citations=prompt.citations)
        lines.append(f"# {prompt.question}\n{answer}\n")
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path
