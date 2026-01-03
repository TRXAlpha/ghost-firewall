from dataclasses import dataclass
import json


@dataclass
class ReportItem:
    timestamp: str
    client: str
    domain: str
    qtype: str
    flags: dict[str, bool]
    score: float
    decision: str


@dataclass
class Report:
    items: list[ReportItem]
    summary: dict[str, int]
    endpoint_findings: list[dict] | None = None
    policy_candidates: list[str] | None = None

    def to_json(self) -> str:
        payload = {
            "summary": self.summary,
            "items": [
                {
                    "timestamp": item.timestamp,
                    "client": item.client,
                    "domain": item.domain,
                    "qtype": item.qtype,
                    "flags": item.flags,
                    "score": item.score,
                    "decision": item.decision,
                }
                for item in self.items
            ],
        }
        if self.endpoint_findings is not None:
            payload["endpoint_findings"] = self.endpoint_findings
        if self.policy_candidates is not None:
            payload["auto_block_candidates"] = self.policy_candidates
        return json.dumps(payload, indent=2)

    def to_text(self) -> str:
        lines = ["AI Firewall Report", "===================", ""]
        lines.append("Summary:")
        for key, value in self.summary.items():
            lines.append(f"- {key}: {value}")
        lines.append("")
        lines.append("Findings:")
        for item in self.items:
            lines.append(
                f"{item.timestamp} {item.client} {item.domain} {item.qtype} score={item.score:.2f} {item.decision} flags={item.flags}"
            )
        if self.endpoint_findings:
            lines.append("")
            lines.append("Endpoint Findings:")
            for finding in self.endpoint_findings:
                lines.append(
                    f"{finding.get('severity','info').upper()} {finding.get('category')}: {finding.get('description')}"
                )
        if self.policy_candidates:
            lines.append("")
            lines.append("Auto-Block Candidates (not enforced):")
            for candidate in self.policy_candidates:
                lines.append(f"- {candidate}")
        return "\n".join(lines)
