from dataclasses import dataclass
import datetime as dt
import re
from typing import Iterable


DNS_PATTERN = re.compile(
    r"^(?P<ts>\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+dnsmasq\[\d+\]:\s+query\[(?P<qtype>\w+)\]\s+(?P<domain>\S+)\s+from\s+(?P<client>\S+)"
)


@dataclass
class DNSQuery:
    timestamp: dt.datetime
    client: str
    domain: str
    qtype: str
    raw: str


def _parse_timestamp(ts: str) -> dt.datetime:
    now = dt.datetime.now()
    try:
        return dt.datetime.strptime(f"{ts} {now.year}", "%b %d %H:%M:%S %Y")
    except ValueError:
        return now


def parse_dns_log(lines: Iterable[str]) -> list[DNSQuery]:
    queries = []
    for line in lines:
        match = DNS_PATTERN.search(line)
        if not match:
            continue
        ts = _parse_timestamp(match.group("ts"))
        queries.append(
            DNSQuery(
                timestamp=ts,
                client=match.group("client"),
                domain=match.group("domain"),
                qtype=match.group("qtype"),
                raw=line.strip(),
            )
        )
    return queries
