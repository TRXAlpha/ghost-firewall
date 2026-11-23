"""Threat-intelligence blocklists: download, parse, match.

This is the part that catches *known* malware, phishing and C2 domains. It is
far more reliable than anomaly scoring, which only guesses at unknown ones."""

import re
import urllib.request
from pathlib import Path

from ai_firewall.domains import normalize, parents

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
_HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}
_SKIP = {"localhost", "localhost.localdomain", "broadcasthost", "local"}


def parse_blocklist_line(line: str) -> str | None:
    """Accepts plain domains, hosts files, '*.domain' and Adblock '||domain^'."""
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith("!") or line.startswith("["):
        return None
    parts = line.split()
    if len(parts) >= 2 and parts[0] in _HOSTS_IPS:
        line = parts[1]
    elif len(parts) != 1:
        return None
    if line.startswith("||"):
        line = line[2:].split("^", 1)[0]
    if line.startswith("*."):
        line = line[2:]
    domain = normalize(line)
    if domain in _SKIP or not _DOMAIN_RE.match(domain):
        return None
    return domain


class ThreatIntel:
    def __init__(self) -> None:
        self.domains: dict[str, str] = {}  # domain -> feed name

    def __len__(self) -> int:
        return len(self.domains)

    def add_lines(self, lines, source: str) -> int:
        added = 0
        for line in lines:
            domain = parse_blocklist_line(line)
            if domain and domain not in self.domains:
                self.domains[domain] = source
                added += 1
        return added

    def load_dir(self, directory: str) -> None:
        for path in sorted(Path(directory).glob("*.txt")):
            with path.open(encoding="utf-8", errors="ignore") as fh:
                self.add_lines(fh, path.stem)

    def match(self, domain: str) -> tuple[str, str] | None:
        """Return (listed_domain, feed) if the domain or any parent is listed."""
        for candidate in parents(domain):
            source = self.domains.get(candidate)
            if source:
                return candidate, source
        return None


def update_feeds(feeds: list[dict], directory: str, timeout: int = 60) -> dict[str, str]:
    """Download each feed to <directory>/<name>.txt. A failed or suspiciously
    small download keeps the previous copy. Returns name -> status."""
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    results = {}
    for feed in feeds:
        name, url = feed.get("name"), feed.get("url", "")
        if not name or not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or not url.startswith("https://"):
            results[str(name)] = "skipped: needs a simple name and an https url"
            continue
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "dns-blocklist-updater"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="ignore")
            count = sum(1 for line in body.splitlines() if parse_blocklist_line(line))
            if count < 10:
                results[name] = f"kept old copy: only {count} domains in download"
                continue
            tmp = out_dir / f"{name}.txt.tmp"
            tmp.write_text(body, encoding="utf-8")
            tmp.replace(out_dir / f"{name}.txt")
            results[name] = f"ok: {count} domains"
        except Exception as exc:  # network errors must not kill the daily run
            results[name] = f"kept old copy: {exc}"
    return results
