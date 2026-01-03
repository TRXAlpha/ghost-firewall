import argparse
from pathlib import Path

from .config import load_config
from .dns_parser import parse_dns_log
from .device_profile import DeviceProfiler
from .anomaly import AnomalyDetector
from .entropy import shannon_entropy
from datetime import datetime

from .endpoint import analyze_endpoint, load_endpoint_snapshot
from .feedback import build_feedback_map, load_feedback
from .online_model import load_model, save_model
from .policy import PolicyConfig, load_policy_state, save_policy_state
from .statistical_model import load_statistical_model, save_statistical_model
from .trm_adapter import load_trm
from .report import Report, ReportItem


def analyze(
    log_path: str,
    config_path: str,
    model_path: str | None = None,
    feedback_path: str | None = None,
    endpoint_path: str | None = None,
    endpoint_baseline_path: str | None = None,
    policy_state_path: str | None = None,
    learn: bool = False,
) -> Report:
    config = load_config(config_path)
    lines = Path(log_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    queries = parse_dns_log(lines)

    profiler = DeviceProfiler()
    detector = AnomalyDetector(config)
    trm_model = load_trm(config.trm_weights)
    online_model = None
    statistical_model = None
    if model_path and config.model_type == "online_logistic":
        online_model = load_model(model_path, config.learning_rate)
    elif model_path and config.model_type == "statistical":
        statistical_model = load_statistical_model(model_path, config.zscore_threshold)
    feedback_map = {}
    if feedback_path:
        feedback_map = build_feedback_map(load_feedback(feedback_path))
    policy_candidates = None
    policy_state = None
    if policy_state_path:
        policy_state = load_policy_state(policy_state_path)

    items = []
    summary = {"total": 0, "recommended": 0, "learned": 0, "endpoint_findings": 0}

    for query in queries:
        summary["total"] += 1
        tld = query.domain.split(".")[-1].lower() if "." in query.domain else ""
        entropy = shannon_entropy(query.domain)
        is_new_tld = profiler.update(query.client, tld, entropy)
        flags, features = detector.score(query, is_new_tld, entropy=entropy, tld=tld)
        if online_model:
            score = online_model.predict_proba(features)
            decision = "recommend" if score >= config.decision_threshold else "allow"
            if learn and feedback_map:
                label = feedback_map.get((query.domain.lower(), query.client))
                if label is None:
                    label = feedback_map.get((query.domain.lower(), None))
                if label is not None:
                    online_model.update(features, label)
                    summary["learned"] += 1
                    if policy_state:
                        policy_state.update(query.domain, label, datetime.utcnow())
        elif statistical_model:
            statistical_model.update(features)
            if learn and feedback_map:
                label = feedback_map.get((query.domain.lower(), query.client))
                if label is None:
                    label = feedback_map.get((query.domain.lower(), None))
                if label is not None:
                    statistical_model.apply_feedback(query.domain, label)
                    summary["learned"] += 1
                    if policy_state:
                        policy_state.update(query.domain, label, datetime.utcnow())
            score = statistical_model.score(features, query.domain)
            decision = "recommend" if score >= config.decision_threshold else "allow"
        else:
            result = trm_model.infer(features)
            score = result.score
            decision = "recommend" if result.decision == "flag" else "allow"

        if decision == "recommend":
            summary["recommended"] += 1
            items.append(
                ReportItem(
                    timestamp=query.timestamp.isoformat(),
                    client=query.client,
                    domain=query.domain,
                    qtype=query.qtype,
                    flags={
                        "entropy": flags.entropy,
                        "length": flags.length,
                        "rare_tld": flags.rare_tld,
                        "burst": flags.burst,
                        "new_tld": flags.new_tld,
                    },
                    score=score,
                    decision=decision,
                )
            )

    if learn and online_model and model_path:
        save_model(model_path, online_model)
    if statistical_model and model_path:
        save_statistical_model(model_path, statistical_model)

    endpoint_findings = None
    if endpoint_path:
        snapshot = load_endpoint_snapshot(endpoint_path)
        baseline = None
        if endpoint_baseline_path:
            baseline = load_endpoint_snapshot(endpoint_baseline_path)
        findings = analyze_endpoint(snapshot, baseline=baseline)
        endpoint_findings = [
            {"category": f.category, "severity": f.severity, "description": f.description}
            for f in findings
        ]
        summary["endpoint_findings"] = len(findings)
    if policy_state and policy_state_path:
        policy_config = PolicyConfig(
            auto_promote_after=config.auto_promote_after,
            auto_promote_decay_days=config.auto_promote_decay_days,
        )
        policy_state.decay(datetime.utcnow(), policy_config.auto_promote_decay_days)
        policy_candidates = policy_state.candidates(policy_config.auto_promote_after)
        save_policy_state(policy_state_path, policy_state)

    return Report(
        items=items,
        summary=summary,
        endpoint_findings=endpoint_findings,
        policy_candidates=policy_candidates,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Firewall DNS analyzer")
    parser.add_argument("--log", required=True, help="Path to Pi-hole or dnsmasq log file")
    parser.add_argument("--config", required=True, help="Path to config JSON")
    parser.add_argument("--model", help="Path to online model JSON (enables learning)")
    parser.add_argument("--feedback", help="Path to feedback JSON for learning")
    parser.add_argument("--endpoint", help="Path to endpoint snapshot JSON for heuristics")
    parser.add_argument("--endpoint-baseline", help="Baseline endpoint snapshot JSON for diffs")
    parser.add_argument("--policy-state", help="Path to policy state JSON for auto-promotion")
    parser.add_argument("--learn", action="store_true", help="Update model using feedback")
    parser.add_argument("--out", help="Output JSON report path")
    parser.add_argument("--text", help="Output text report path")
    args = parser.parse_args()

    report = analyze(
        args.log,
        args.config,
        model_path=args.model,
        feedback_path=args.feedback,
        endpoint_path=args.endpoint,
        endpoint_baseline_path=args.endpoint_baseline,
        policy_state_path=args.policy_state,
        learn=args.learn,
    )

    if args.out:
        Path(args.out).write_text(report.to_json(), encoding="utf-8")
    if args.text:
        Path(args.text).write_text(report.to_text(), encoding="utf-8")


if __name__ == "__main__":
    main()
