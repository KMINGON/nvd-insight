from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Sequence, Tuple

from .. import config

try:
    from langchain_community.vectorstores import FAISS
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_openai import OpenAIEmbeddings, ChatOpenAI
    from langchain_community.embeddings import HuggingFaceEmbeddings
except ImportError:  # pragma: no cover
    OpenAIEmbeddings = None
    FAISS = None
    ChatPromptTemplate = None
    ChatOpenAI = None
    HuggingFaceEmbeddings = None


RETRIEVAL_PROMPT = ChatPromptTemplate.from_messages(
    [
        ("system", "{system_prompt}"),
        (
            "human",
            "이전 대화:\n{history}\n\n"
            "참고 문서:\n{context}\n\n"
            "사용자 질문: {question}\n"
            "답변은 반드시 문서 근거를 바탕으로 작성하세요.",
        ),
    ]
) if ChatPromptTemplate is not None else None


# 기능: 검색 결과 한 건의 텍스트/점수/메타데이터를 묶은 컨테이너.
@dataclass
class RetrievalResult:
    """검색 결과 1건에 대한 정보 컨테이너."""

    text: str
    score: float
    metadata: dict


# 기능: RAG 검색기의 경로/모델 설정을 묶은 데이터 클래스.
@dataclass
class RetrieverConfig:
    """RAG 검색기가 참고할 경로/모델 파라미터."""

    index_dir: Path = field(default_factory=lambda: Path(config.FAISS_INDEX_DIR) / "cve_cwe_index")
    embedding_model: str = config.DEFAULT_EMBEDDING_MODEL
    embedding_backend: str = config.EMBEDDING_BACKEND
    chat_model: str = config.DEFAULT_CHAT_MODEL
    top_k: int = config.DEFAULT_TOP_K


class RagRetriever:
    """FAISS+LangChain 스택을 사용하는 검색/응답 래퍼."""

    def __init__(self, retriever_config: RetrieverConfig | None = None) -> None:
        self.config = retriever_config or RetrieverConfig()
        self.vector_store: FAISS | None = None
        self.llm = None
        self.is_loaded = False
        self.prompt_template = RETRIEVAL_PROMPT

    # 기능: FAISS 인덱스와 임베딩/LLM 클라이언트를 초기화한다.
    def load(self) -> None:
        """FAISS 인덱스를 읽어들이고 임베딩/LLM 클라이언트를 초기화한다."""
        if FAISS is None:
            raise ImportError("LangChain FAISS dependency is missing")
        embeddings = self._resolve_embeddings()
        if not self.config.index_dir.exists():
            raise FileNotFoundError(self.config.index_dir)
        self.vector_store = FAISS.load_local(  # type: ignore[attr-defined]
            folder_path=str(self.config.index_dir),
            embeddings=embeddings,
            allow_dangerous_deserialization=True,
        )
        if ChatOpenAI is not None and config.OPENAI_API_KEY:
            # TODO: 로컬 LLM이나 Azure 엔드포인트로도 전환할 수 있도록 확장한다.
            self.llm = ChatOpenAI(
                model=self.config.chat_model,
                temperature=0.1,
                openai_api_key=config.OPENAI_API_KEY,
            )
        self.is_loaded = True

    # 기능: 쿼리 및 필터를 사용해 유사도 검색을 수행한다.
    def retrieve(self, query: str, filters: dict | None = None, top_k: int | None = None) -> List[RetrievalResult]:
        """쿼리와 메타데이터 필터를 이용해 유사도 검색을 수행한다.

        매개변수:
            query (str): 사용자 질문 또는 보고서 요청.
            filters (dict | None): 연도·CVE ID 등 메타데이터 조건.
            top_k (int | None): 반환할 문서 수.

        반환값:
            List[RetrievalResult]: 검색된 문서와 점수 목록.
        """
        if not self.is_loaded or self.vector_store is None:
            raise RuntimeError("Vector index is not loaded. Call load() first.")
        docs_with_scores = self._search_with_filters(
            query=query,
            filters=filters,
            top_k=top_k or self.config.top_k,
        )
        results: List[RetrievalResult] = []
        for doc, score in docs_with_scores:
            results.append(
                RetrievalResult(
                    text=getattr(doc, "page_content", ""),
                    score=score,
                    metadata=getattr(doc, "metadata", {}),
                )
            )
        return results

    # 기능: 검색된 문맥과 히스토리를 결합해 LLM 응답을 생성한다.
    def generate_response(
        self,
        system_prompt: str,
        user_prompt: str,
        filters: dict | None = None,
        history: List[dict] | None = None,
        top_k: int | None = None,
    ) -> str:
        """검색 문맥을 포함해 답변 텍스트를 생성한다.

        매개변수:
            system_prompt (str): 모델 역할·톤을 정의하는 시스템 메시지.
            user_prompt (str): 데이터프레임 요약 혹은 실제 질문 등 사용자 입력.
            filters (dict | None): 검색 범위를 좁히는 메타데이터 필터.
            history (List[dict] | None): 이전 대화 히스토리.

        반환값:
            str: LLM 응답(또는 예외 상황 시 문자열).
        """
        if not self.is_loaded or self.vector_store is None or self.llm is None:
            raise RuntimeError("Retriever is not loaded. Call load() before generate_response().")
        history_text = self._format_history(history)
        docs_with_scores = self._search_with_filters(
            query=user_prompt,
            filters=filters,
            top_k=top_k or self.config.top_k,
        )
        context = self._format_context(docs_with_scores)
        prompt = self.prompt_template or ChatPromptTemplate.from_template(
            "System:\n{system_prompt}\n\nHistory:\n{history}\n\nContext:\n{context}\n\nQuestion: {question}"
        )
        messages = prompt.format_messages(
            system_prompt=system_prompt,
            history=history_text,
            context=context,
            question=user_prompt,
        )
        response = self.llm.invoke(messages)
        return getattr(response, "content", str(response))

    # 기능: 간단한 질의응답 흐름을 위한 헬퍼.
    def ask(self, question: str, top_k: int = 5, citations: bool = True) -> str:
        """레거시 보고서 흐름을 위한 간단 헬퍼."""
        _ = citations  # TODO: 인용 포맷이 완성되면 활용하도록 확장한다.
        return self.generate_response(
            system_prompt="You are a helpful security analysis assistant.",
            user_prompt=question,
            filters=None,
            history=[],
            top_k=top_k,
        )

    @staticmethod
    # 기능: 대화 히스토리를 단일 문자열로 포맷해 LLM 프롬프트에 넣는다.
    def _format_history(history: List[dict] | None) -> str:
        if not history:
            return "없음"
        return "\n".join(f"{item['role']}: {item['content']}" for item in history)

    @staticmethod
    # 기능: 빈 값이 제거된 필터 사전을 생성해 내부 검색에서 사용한다.
    def _normalize_filters(filters: dict | None) -> dict:
        if not filters:
            return {}
        normalized: dict[str, Any] = {}
        for key, value in filters.items():
            if value is None:
                continue
            if isinstance(value, list):
                cleaned = [item for item in value if item not in (None, "")]
                if not cleaned:
                    continue
                normalized[key] = cleaned
            else:
                if value in (None, ""):
                    continue
                normalized[key] = value
        return normalized

    # 기능: 메타데이터 필터를 적용해 FAISS 유사도 검색 결과를 후처리한다.
    def _search_with_filters(
        self,
        query: str,
        filters: dict | None,
        top_k: int,
    ) -> List[Tuple[Any, float]]:
        """FAISS가 메타데이터 필터를 지원하지 않으므로 후처리로 필터링한다."""
        if self.vector_store is None:
            raise RuntimeError("Vector index is not loaded.")
        normalized_filters = self._normalize_filters(filters)
        search_limit = max(top_k * 2, top_k)
        docs_with_scores = self.vector_store.similarity_search_with_score(query, k=search_limit)
        if not normalized_filters:
            return docs_with_scores[:top_k]
        filtered: List[Tuple[Any, float]] = []
        for doc, score in docs_with_scores:
            if self._matches_filters(doc, normalized_filters):
                filtered.append((doc, score))
            if len(filtered) >= top_k:
                break
        return filtered if filtered else docs_with_scores[:top_k]

    @staticmethod
    # 기능: 문서 메타데이터가 필터 조건을 만족하는지 검사한다.
    def _matches_filters(doc: Any, filters: dict) -> bool:
        metadata = getattr(doc, "metadata", {}) or {}
        for key, expected in filters.items():
            candidate = metadata.get(key)
            if isinstance(expected, list):
                expected_values = {str(item) for item in expected if item not in (None, "")}
                if not expected_values:
                    continue
                if isinstance(candidate, list):
                    candidate_values = {str(item) for item in candidate if item not in (None, "")}
                    if not candidate_values.intersection(expected_values):
                        return False
                else:
                    if str(candidate) not in expected_values:
                        return False
            else:
                if isinstance(candidate, list):
                    candidate_values = {str(item) for item in candidate if item not in (None, "")}
                    if str(expected) not in candidate_values:
                        return False
                elif str(candidate) != str(expected):
                    return False
        return True

    @staticmethod
    # 기능: 검색 결과 목록을 LLM 프롬프트에 삽입할 텍스트로 변환한다.
    def _format_context(docs_with_scores: Sequence[Tuple[Any, float]]) -> str:
        if not docs_with_scores:
            return "검색된 문서가 없습니다."
        blocks = []
        for idx, (doc, score) in enumerate(docs_with_scores, start=1):
            metadata = getattr(doc, "metadata", {}) or {}
            label = metadata.get("cveId") or metadata.get("year") or f"doc-{idx}"
            snippet = getattr(doc, "page_content", "")
            blocks.append(f"[{label}] score={score:.3f}\n{snippet}")
        return "\n\n".join(blocks)

    # 기능: 설정된 백엔드에 따라 OpenAI 혹은 로컬 임베딩을 생성한다.
    def _resolve_embeddings(self):
        backend = (self.config.embedding_backend or "local").lower()
        model_name = self.config.embedding_model or config.DEFAULT_EMBEDDING_MODEL
        if backend == "openai":
            if OpenAIEmbeddings is None:
                raise ImportError("LangChain OpenAIEmbeddings dependency is missing")
            if not config.OPENAI_API_KEY:
                raise EnvironmentError("OPENAI_API_KEY is not configured")
            return OpenAIEmbeddings(model=model_name, openai_api_key=config.OPENAI_API_KEY)
        if HuggingFaceEmbeddings is None:
            raise ImportError(
                "HuggingFaceEmbeddings dependency missing. Install sentence-transformers."
            )
        return HuggingFaceEmbeddings(model_name=model_name)
