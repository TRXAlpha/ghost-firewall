"""Domain helpers. No public-suffix-list dependency: a small built-in table
covers the common two-level suffixes, which is enough for grouping."""

_TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.br", "net.br", "org.br", "com.cn", "net.cn", "org.cn",
    "co.in", "net.in", "org.in", "co.za", "org.za", "com.mx", "com.ar",
    "com.tr", "com.sg", "com.hk", "com.tw", "co.kr", "or.kr", "com.ua",
    "co.il", "com.pl", "com.ru", "com.es", "com.co", "com.my", "co.id",
}


def normalize(domain: str) -> str:
    return (domain or "").strip().strip(".").lower()


def tld(domain: str) -> str:
    domain = normalize(domain)
    return domain.rsplit(".", 1)[-1] if "." in domain else ""


def registered_domain(domain: str) -> str:
    """Best-effort registrable domain: a.b.example.co.uk -> example.co.uk."""
    domain = normalize(domain)
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    if ".".join(parts[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def subdomain(domain: str) -> str:
    """Everything left of the registered domain ('' if none)."""
    domain = normalize(domain)
    reg = registered_domain(domain)
    return domain[: -len(reg) - 1] if len(domain) > len(reg) else ""


def parents(domain: str):
    """Yield the domain and each parent: a.b.c -> a.b.c, b.c (never the bare TLD)."""
    parts = normalize(domain).split(".")
    for i in range(len(parts) - 1):
        yield ".".join(parts[i:])
