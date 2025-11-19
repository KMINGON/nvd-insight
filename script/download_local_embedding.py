#!/usr/bin/env python
from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from huggingface_hub import snapshot_download

from src import config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Download sentence-transformers models for offline use.")
    parser.add_argument(
        "--model",
        type=str,
        default=config.LOCAL_EMBEDDING_MODEL,
        help="Hugging Face model identifier (default: %(default)s)",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=None,
        help="Optional directory to store the downloaded snapshot (defaults to HF cache).",
    )
    parser.add_argument(
        "--revision",
        type=str,
        default=None,
        help="Optional model revision / commit hash.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    kwargs: dict = {"repo_id": args.model}
    if args.target_dir:
        kwargs["local_dir"] = str(args.target_dir)
        kwargs["local_dir_use_symlinks"] = False
    if args.revision:
        kwargs["revision"] = args.revision
    snapshot_path = snapshot_download(**kwargs)
    print(f"Model downloaded to: {snapshot_path}")


if __name__ == "__main__":
    main()
