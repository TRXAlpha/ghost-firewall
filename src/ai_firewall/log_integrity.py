import hashlib
from pathlib import Path
from typing import Iterable


def hash_log_lines(lines: Iterable[str]) -> str:
    hasher = hashlib.sha256()
    for line in lines:
        hasher.update(line.encode("utf-8", errors="ignore"))
        hasher.update(b"\n")  # keep line boundaries: ["ab","c"] != ["a","bc"]
    return hasher.hexdigest()


def _last_link(chain_path: Path) -> str:
    if not chain_path.exists():
        return "0" * 64
    entries = [l for l in chain_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    return entries[-1].split()[0] if entries else "0" * 64


def append_hash_chain(log_path: str, chain_path: str) -> str:
    """Append one link: sha256(previous_link + log_hash). Each line of the
    chain file is '<link> <log_hash>'. Editing any earlier log breaks every
    later link. Keep a copy of the chain file somewhere the logger cannot write."""
    lines = Path(log_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    log_hash = hash_log_lines(lines)
    chain = Path(chain_path)
    link = hashlib.sha256((_last_link(chain) + log_hash).encode()).hexdigest()
    with chain.open("a", encoding="utf-8") as fh:
        fh.write(f"{link} {log_hash}\n")
    return link


def verify_hash_chain(chain_path: str) -> bool:
    prev = "0" * 64
    for entry in Path(chain_path).read_text(encoding="utf-8").splitlines():
        if not entry.strip():
            continue
        link, log_hash = entry.split()
        if hashlib.sha256((prev + log_hash).encode()).hexdigest() != link:
            return False
        prev = link
    return True
