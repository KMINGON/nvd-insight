#!/usr/bin/env python
from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src import config
from src.rag.indexer import VectorIndexer


def parse_args() -> argparse.Namespace:
    """커맨드라인 인자를 파싱해 인덱싱 파라미터를 반환한다."""
    parser = argparse.ArgumentParser(
        description="Build FAISS index files from processed CVE/CWE datasets."
    )
    parser.add_argument(
        "--dataset-path",
        type=Path,
        default=None,
        help="Processed dataset directory (defaults to config.PROCESSED_DATASET_DIR).",
    )
    parser.add_argument(
        "--index-dir",
        type=Path,
        default=None,
        help="Directory to place the FAISS index (defaults to config.FAISS_INDEX_DIR).",
    )
    parser.add_argument(
        "--embedding-model",
        type=str,
        default=None,
        help="Embedding model name (defaults to config.DEFAULT_EMBEDDING_MODEL).",
    )
    parser.add_argument(
        "--embedding-backend",
        type=str,
        default=None,
        choices=["local", "openai"],
        help="Embedding backend to use (local or openai). Defaults to config.EMBEDDING_BACKEND.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=128,
        help="Number of documents per embedding batch (default: 128).",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bar output.",
    )
    return parser.parse_args()


def main() -> None:
    """CLI 인자를 읽은 뒤 VectorIndexer로 FAISS 인덱스를 생성한다."""
    args = parse_args()
    # 인자가 비어 있으면 config에 정의된 기본 경로/모델을 사용한다.
    dataset_path = args.dataset_path or config.PROCESSED_DATASET_DIR
    index_dir = args.index_dir or config.FAISS_INDEX_DIR
    embedding_model = args.embedding_model or config.DEFAULT_EMBEDDING_MODEL
    embedding_backend = args.embedding_backend or config.EMBEDDING_BACKEND
    batch_size = max(1, args.batch_size)
    show_progress = not args.no_progress

    # VectorIndexer는 데이터 로드와 빌드를 분리하므로 두 단계로 호출한다.
    indexer = VectorIndexer(
        dataset_path=dataset_path,
        index_dir=index_dir,
        embedding_model=embedding_model,
        embedding_backend=embedding_backend,
    )
    docs = indexer.load_documents()
    index_path = indexer.build(docs, batch_size=batch_size, show_progress=show_progress)
    print(f"FAISS index saved to: {index_path}")


if __name__ == "__main__":
    main()
