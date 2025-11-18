"""RAG 서브패키지 공개 API.

런타임 경고를 피하기 위해 지연 임포트를 사용한다.
"""

__all__ = ["VectorIndexer", "RagRetriever", "RetrieverConfig"]


def __getattr__(name):
    if name == "VectorIndexer":
        from .indexer import VectorIndexer as _VectorIndexer

        return _VectorIndexer
    if name in {"RagRetriever", "RetrieverConfig"}:
        from .retriever import RagRetriever as _RagRetriever, RetrieverConfig as _RetrieverConfig

        return _RagRetriever if name == "RagRetriever" else _RetrieverConfig
    raise AttributeError(name)
