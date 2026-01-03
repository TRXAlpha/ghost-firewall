import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class EndpointFinding:
    category: str
    severity: str
    description: str


def _is_user_path(path: str) -> bool:
    lowered = path.lower()
    return any(
        token in lowered
        for token in ["\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\"]
    )


def _is_private_ip(ip: str) -> bool:
    if not ip or ip == "0.0.0.0":
        return True
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("127.") or ip.startswith("::1"):
        return True
    if ip.startswith("172."):
        try:
            octet = int(ip.split(".")[1])
            return 16 <= octet <= 31
        except (IndexError, ValueError):
            return False
    return False


def load_endpoint_snapshot(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _extract_event_findings(events: list[dict]) -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []
    high_signal_ids = {
        7045: "New service installed",
        4698: "Scheduled task created",
        4720: "New user account created",
        4625: "Failed logon",
        1102: "Security log cleared",
        4104: "PowerShell script block logging",
    }
    for event in events:
        event_id = event.get("id")
        if event_id not in high_signal_ids:
            continue
        message = event.get("message", "") or ""
        findings.append(
            EndpointFinding(
                category="event_log",
                severity="medium" if event_id in {4625, 4104} else "high",
                description=f"{high_signal_ids[event_id]} (Event ID {event_id}) {message[:160]}",
            )
        )
    return findings


def _diff_startup(current: list[dict], baseline: list[dict]) -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []
    baseline_keys = {(item.get("name"), item.get("command")) for item in baseline}
    for item in current:
        key = (item.get("name"), item.get("command"))
        if key in baseline_keys:
            continue
        findings.append(
            EndpointFinding(
                category="startup_diff",
                severity="medium",
                description=f"New startup entry: {item.get('name')} ({item.get('command')})",
            )
        )
    return findings


def _diff_tasks(current: list[dict], baseline: list[dict]) -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []
    baseline_keys = {(item.get("name"), item.get("action")) for item in baseline}
    for item in current:
        key = (item.get("name"), item.get("action"))
        if key in baseline_keys:
            continue
        findings.append(
            EndpointFinding(
                category="task_diff",
                severity="medium",
                description=f"New scheduled task: {item.get('name')} ({item.get('action')})",
            )
        )
    return findings


def _diff_services(current: list[dict], baseline: list[dict]) -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []
    baseline_keys = {(item.get("name"), item.get("display_name")) for item in baseline}
    for item in current:
        key = (item.get("name"), item.get("display_name"))
        if key in baseline_keys:
            continue
        findings.append(
            EndpointFinding(
                category="service_diff",
                severity="medium",
                description=f"New service: {item.get('name')} ({item.get('display_name')})",
            )
        )
    return findings


def analyze_endpoint(snapshot: dict, baseline: dict | None = None) -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []

    for proc in snapshot.get("processes", []):
        path = proc.get("path") or ""
        signature = proc.get("signature_status") or ""
        if path and _is_user_path(path) and signature.lower() != "valid":
            findings.append(
                EndpointFinding(
                    category="process",
                    severity="high",
                    description=f"Unsigned process in user path: {proc.get('name')} ({path})",
                )
            )

    for item in snapshot.get("startup_items", []):
        path = item.get("command") or ""
        signature = item.get("signature_status") or ""
        if path and _is_user_path(path) and signature.lower() != "valid":
            findings.append(
                EndpointFinding(
                    category="startup",
                    severity="medium",
                    description=f"Startup entry from user path: {item.get('name')} ({path})",
                )
            )

    for task in snapshot.get("scheduled_tasks", []):
        action = task.get("action") or ""
        if action and _is_user_path(action):
            findings.append(
                EndpointFinding(
                    category="scheduled_task",
                    severity="medium",
                    description=f"Scheduled task executing from user path: {task.get('name')} ({action})",
                )
            )

    for conn in snapshot.get("tcp_connections", []):
        remote = conn.get("remote_address") or ""
        if _is_private_ip(remote):
            continue
        proc = conn.get("process_name") or ""
        signature = conn.get("signature_status") or ""
        if signature.lower() != "valid":
            findings.append(
                EndpointFinding(
                    category="network",
                    severity="high",
                    description=f"Unsigned process with public connection: {proc} -> {remote}",
                )
            )

    findings.extend(_extract_event_findings(snapshot.get("event_logs", [])))

    if baseline:
        findings.extend(
            _diff_startup(
                snapshot.get("startup_items", []),
                baseline.get("startup_items", []),
            )
        )
        findings.extend(
            _diff_tasks(
                snapshot.get("scheduled_tasks", []),
                baseline.get("scheduled_tasks", []),
            )
        )
        findings.extend(
            _diff_services(
                snapshot.get("services", []),
                baseline.get("services", []),
            )
        )

    return findings
