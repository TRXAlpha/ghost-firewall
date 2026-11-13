"""Write a blocklist file that Pi-hole (or AdGuard Home, or dnsmasq) enforces.

This is the enforcement hand-off: this tool decides, your DNS server blocks."""

from datetime import datetime, timezone
from pathlib import Path

from ai_firewall.domains import normalize, parents
from ai_firewall.intel import parse_blocklist_line

FORMATS = ("abp", "domains", "dnsmasq")


def is_protected(domain: str, never_block: set[str]) -> bool:
    """True if blocking `domain` would hit a never-block entry: the domain is
    one, sits under one, or is a parent of one."""
    domain = normalize(domain)
    if any(p in never_block for p in parents(domain)):
        return True
    return any(entry.endswith("." + domain) for entry in never_block)


def _parse_existing(path: Path) -> set[str]:
    found = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("address=/"):
                line = line.split("/")[1]
            domain = parse_blocklist_line(line)
            if domain:
                found.add(domain)
    return found


def write_blocklist(
    path: str,
    domains: set[str],
    never_block: set[str],
    unblock: set[str] = frozenset(),
    fmt: str = "abp",
) -> list[str]:
    """Merge `domains` into the file at `path` and return the final list.
    Entries are cumulative across runs; `unblock` (allow-labelled domains) and
    anything protected by `never_block` are removed."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown blocklist format: {fmt}")
    out = Path(path)
    merged = _parse_existing(out) | {normalize(d) for d in domains}
    kept = {d for d in merged if d and d not in unblock and not is_protected(d, never_block)}
    # A parent entry already covers its subdomains: drop the redundant children.
    final = sorted(d for d in kept if not any(p in kept for p in list(parents(d))[1:]))
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if fmt == "abp":
        header = [f"! Ghost Firewall blocklist, {len(final)} domains, {stamp}"]
        body = [f"||{d}^" for d in final]
    elif fmt == "dnsmasq":
        header = [f"# Ghost Firewall blocklist, {len(final)} domains, {stamp}"]
        body = [f"address=/{d}/#" for d in final]
    else:
        header = [f"# Ghost Firewall blocklist, {len(final)} domains, {stamp}"]
        body = final
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text("\n".join(header + body) + "\n", encoding="utf-8")
    tmp.replace(out)
    return final
