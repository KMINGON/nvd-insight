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
    """FAISS + LangChain 구성요소를 감싼 RAG 전용 래퍼.

    저장된 FAISS 인덱스를 불러와 쿼리를 임베딩하고, 가장 유사한 문서를 조회한 뒤
    필요하면 OpenAI 또는 로컬 LLM을 호출해 근거가 있는 답변을 만든다.
    """

    def __init__(self, retriever_config: RetrieverConfig | None = None) -> None:
        """구성을 저장하고 FAISS/LLM 클라이언트용 플레이스홀더를 준비한다.

        매개변수:
            retriever_config: 모델·인덱스 파라미터가 담긴 선택적 설정.
        """
        self.config = retriever_config or RetrieverConfig()
        # 실제 객체는 load()를 호출한 이후에 설정되므로 None으로 초기화한다.
        self.vector_store: FAISS | None = None
        self.llm = None
        self.is_loaded = False
        self.prompt_template = RETRIEVAL_PROMPT

    # 기능: FAISS 인덱스와 임베딩/LLM 클라이언트를 초기화한다.
    def load(self) -> None:
        """FAISS 인덱스를 읽고 임베딩/챗 모델을 초기화한다.

        예외:
            ImportError: LangChain/FAISS 의존성이 없을 때.
            FileNotFoundError: 설정된 인덱스 디렉터리가 존재하지 않을 때.
        """
        if FAISS is None:
            raise ImportError("LangChain FAISS dependency is missing")
        # 설정에 맞는 임베딩 백엔드를 먼저 준비한다.
        embeddings = self._resolve_embeddings()
        if not self.config.index_dir.exists():
            raise FileNotFoundError(self.config.index_dir)
        # LangChain의 load_local을 호출하며 allow_dangerous_deserialization 옵션을 반드시 명시한다.
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
        # load가 성공적으로 끝나면 플래그를 올려 API 호출을 허용한다.
        self.is_loaded = True

    # 기능: 쿼리 및 필터를 사용해 유사도 검색을 수행한다.
    def retrieve(self, query: str, filters: dict | None = None, top_k: int | None = None) -> List[RetrievalResult]:
        """필요 시 메타데이터 필터를 적용해 유사도 검색을 수행한다.

        매개변수:
            query: 자연어 질문 또는 요약 요청.
            filters: 연도·벤더·CWE 등 선택적 메타데이터 제약 조건.
            top_k: 반환할 문서 최대 개수.

        반환값:
            스니펫과 점수를 담은 RetrievalResult 리스트.

        예외:
            RuntimeError: 벡터 스토어가 아직 로드되지 않은 경우.
        """
        if not self.is_loaded or self.vector_store is None:
            raise RuntimeError("Vector index is not loaded. Call load() first.")
        # FAISS는 필터를 직접 지원하지 않으므로 내부 헬퍼로 검색+후처리를 수행한다.
        docs_with_scores = self._search_with_filters(
            query=query,
            filters=filters,
            top_k=top_k or self.config.top_k,
        )
        results: List[RetrievalResult] = []
        for doc, score in docs_with_scores:
            # LangChain Document의 page_content/metadata 속성을 안전하게 꺼내 컨테이너에 담는다.
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
        """검색 결과를 근거로 삼는 LLM 응답을 생성한다.

        매개변수:
            system_prompt: 모델의 역할과 톤을 정의하는 메시지.
            user_prompt: 실제 질문 또는 요약하고 싶은 텍스트.
            filters: 검색 전에 적용할 메타데이터 필터.
            history: 대화 연속성을 위한 이전 히스토리.
            top_k: 프롬프트에 투입할 문서 수.

        반환값:
            챗 모델이 생성한 문자열.

        예외:
            RuntimeError: FAISS 또는 LLM 클라이언트가 준비되지 않은 경우.
        """
        if not self.is_loaded or self.vector_store is None or self.llm is None:
            raise RuntimeError("Retriever is not loaded. Call load() before generate_response().")
        # 히스토리는 "\n"으로 연결해 시스템 프롬프트에 삽입하기 좋은 단일 문자열로 만든다.
        history_text = self._format_history(history)
        # 사용자가 입력한 문장을 기준으로 다시 검색을 수행해 최신 문맥을 확보한다.
        docs_with_scores = self._search_with_filters(
            query=user_prompt,
            filters=filters,
            top_k=top_k or self.config.top_k,
        )
        # 검색 결과를 사람이 읽을 수 있는 블록으로 만들어 프롬프트에 삽입한다.
        context = self._format_context(docs_with_scores)
        prompt = self.prompt_template or ChatPromptTemplate.from_template(
            "System:\n{system_prompt}\n\nHistory:\n{history}\n\nContext:\n{context}\n\nQuestion: {question}"
        )
        # ChatPromptTemplate이 반환한 메시지 객체 배열을 그대로 LLM에 전달한다.
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
        """기본 프롬프트를 사용해 텍스트만 반환하는 간단 헬퍼.

        매개변수:
            question: CVE/CWE 관련 사용자 질문.
            top_k: 답변에 사용할 문서 개수.
            citations: 추후 인용 포맷 확장용 자리표시자.

        반환값:
            ``generate_response``가 생성한 문자열.
        """
        _ = citations  # TODO: 인용 포맷이 완성되면 활용하도록 확장한다.
        # ask()는 단순화를 위해 독립된 프롬프트/히스토리 없이 generate_response에 위임한다.
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
        """LangChain 프롬프트에 넣기 위해 대화 히스토리를 문자열로 직렬화한다."""
        if not history:
            return "없음"
        # history는 {"role": str, "content": str} 형식을 갖는다고 가정한다.
        return "\n".join(f"{item['role']}: {item['content']}" for item in history)

    @staticmethod
    # 기능: 빈 값이 제거된 필터 사전을 생성해 내부 검색에서 사용한다.
    def _normalize_filters(filters: dict | None) -> dict:
        """필터 사전에서 빈 값을 제거하고 리스트 항목을 정규화한다."""
        if not filters:
            return {}
        normalized: dict[str, Any] = {}
        for key, value in filters.items():
            if value is None:
                continue
            if isinstance(value, list):
                # 리스트형 필터는 빈 문자열을 제거하고 남은 값만 유지한다.
                cleaned = [item for item in value if item not in (None, "")]
                if not cleaned:
                    continue
                normalized[key] = cleaned
            else:
                # 단일 값 필터 역시 공백 문자열은 제외한다.
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
        """FAISS 검색을 실행한 뒤 필요하면 메타데이터 필터를 수동 적용한다.

        매개변수:
            query: 사용자의 검색 문자열.
            filters: ``_normalize_filters``로 정제한 메타데이터 필터.
            top_k: 필터링 후 원하는 최대 결과 수.

        반환값:
            LangChain 문서와 점수 쌍의 리스트.
        """
        if self.vector_store is None:
            raise RuntimeError("Vector index is not loaded.")
        normalized_filters = self._normalize_filters(filters)
        # 필터로 인해 많은 문서가 빠질 수 있으므로 기본 top_k의 2배 이상을 먼저 가져온다.
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
        # 필터 결과가 비어 있을 경우에는 원본 검색 결과라도 최소 개수만큼 반환한다.
        return filtered if filtered else docs_with_scores[:top_k]

    @staticmethod
    # 기능: 문서 메타데이터가 필터 조건을 만족하는지 검사한다.
    def _matches_filters(doc: Any, filters: dict) -> bool:
        """문서가 모든 메타데이터 조건을 만족하면 True를 반환한다."""
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
        """검색된 문서를 프롬프트 삽입용 가독성 있는 블록으로 변환한다."""
        if not docs_with_scores:
            return "검색된 문서가 없습니다."
        blocks = []
        for idx, (doc, score) in enumerate(docs_with_scores, start=1):
            metadata = getattr(doc, "metadata", {}) or {}
            label = metadata.get("cveId") or metadata.get("year") or f"doc-{idx}"
            snippet = getattr(doc, "page_content", "")
            # 각 블록에 점수와 레이블을 붙여 LLM이 근거를 명확히 구분할 수 있게 한다.
            blocks.append(f"[{label}] score={score:.3f}\n{snippet}")
        return "\n\n".join(blocks)

    # 기능: 설정된 백엔드에 따라 OpenAI 혹은 로컬 임베딩을 생성한다.
    def _resolve_embeddings(self):
        """설정에 따라 OpenAI 또는 HuggingFace 임베딩 모델을 생성한다."""
        backend = (self.config.embedding_backend or "local").lower()
        model_name = self.config.embedding_model or config.DEFAULT_EMBEDDING_MODEL
        if backend == "openai":
            if OpenAIEmbeddings is None:
                raise ImportError("LangChain OpenAIEmbeddings dependency is missing")
            if not config.OPENAI_API_KEY:
                raise EnvironmentError("OPENAI_API_KEY is not configured")
            # OpenAI 백엔드일 경우 API 키와 모델명을 그대로 전달한다.
            return OpenAIEmbeddings(model=model_name, openai_api_key=config.OPENAI_API_KEY)
        if HuggingFaceEmbeddings is None:
            raise ImportError(
                "HuggingFaceEmbeddings dependency missing. Install sentence-transformers."
            )
        # 로컬 백엔드는 sentence-transformers 모델명을 그대로 사용한다.
        return HuggingFaceEmbeddings(model_name=model_name)
