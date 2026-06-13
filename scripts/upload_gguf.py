#!/usr/bin/env python3
"""Upload a GGUF file to a HuggingFace repo.

    python scripts/upload_gguf.py --blob <path> --repo gdfhhjk/spectrida-re-gguf

Requires: pip install huggingface_hub  +  a logged-in token (huggingface-cli login).
"""
import argparse
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--blob", required=True, help="Path to the .gguf file")
    ap.add_argument("--repo", required=True, help="HF repo id, e.g. user/model-gguf")
    ap.add_argument("--name", default="model-Q4_K_M.gguf", help="Filename in the repo")
    ap.add_argument("--private", action="store_true")
    args = ap.parse_args()

    blob = Path(args.blob).expanduser()
    if not blob.is_file():
        raise SystemExit(f"not a file: {blob}")

    from huggingface_hub import create_repo, upload_file

    create_repo(args.repo, repo_type="model", exist_ok=True, private=args.private)
    print(f"uploading {blob} -> {args.repo}/{args.name} …")
    upload_file(path_or_fileobj=str(blob), path_in_repo=args.name,
                repo_id=args.repo, repo_type="model", commit_message="upload GGUF")
    print(f"done: https://huggingface.co/{args.repo}")


if __name__ == "__main__":
    main()
