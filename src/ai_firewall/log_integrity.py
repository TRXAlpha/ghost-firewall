import hashlib
from pathlib import Path
from typing import Iterable


def hash_log_lines(lines: Iterable[str]) -> str:
    hasher = hashlib.sha256()
    for line in lines:
        hasher.update(line.encode("utf-8", errors="ignore"))
    return hasher.hexdigest()


def append_hash_chain(log_path: str, chain_path: str) -> str:
    lines = Path(log_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    digest = hash_log_lines(lines)
    Path(chain_path).write_text(digest, encoding="utf-8")
    return digest
