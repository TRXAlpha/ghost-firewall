from dataclasses import dataclass
import datetime as dt
import re
from typing import Iterable

from ai_firewall.domains import normalize

# Matches both Pi-hole's own log ("Nov 11 10:00:01 dnsmasq[1]: query[A] ...")
# and syslog-forwarded dnsmasq lines that carry a hostname before "dnsmasq".
DNS_PATTERN = re.compile(
    r"^(?P<ts>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?:\S+\s+)?dnsmasq(?:\[\d+\])?:\s+"
    r"(?:\d+\s+\S+\s+)?"  # optional "log-queries=extra" serial and client/port
    r"query\[(?P<qtype>[\w-]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<client>\S+)"
)


@dataclass
class DNSQuery:
    timestamp: dt.datetime
    client: str
    domain: str
    qtype: str
    raw: str


def _parse_timestamp(ts: str, now: dt.datetime | None = None) -> dt.datetime:
    """dnsmasq timestamps have no year. Assume the current year, and roll back
    one year if that lands in the future (a December log read in January)."""
    now = now or dt.datetime.now()
    for year in (now.year, now.year - 1):
        try:
            parsed = dt.datetime.strptime(f"{ts} {year}", "%b %d %H:%M:%S %Y")
        except ValueError:  # e.g. Feb 29 in a non-leap year
            continue
        if parsed <= now + dt.timedelta(days=1):
            return parsed
    return now


def parse_dns_log(lines: Iterable[str]) -> list[DNSQuery]:
    queries = []
    for line in lines:
        match = DNS_PATTERN.search(line)
        if not match:
            continue
        domain = normalize(match.group("domain"))
        if not domain:
            continue
        queries.append(
            DNSQuery(
                timestamp=_parse_timestamp(match.group("ts")),
                client=match.group("client"),
                domain=domain,
                qtype=match.group("qtype"),
                raw=line.strip(),
            )
        )
    return queries
