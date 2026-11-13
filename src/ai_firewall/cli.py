import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):  # allow "python src/ai_firewall/cli.py"
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ai_firewall.anomaly import AnomalyDetector
from ai_firewall.blocklist import FORMATS, is_protected, write_blocklist
from ai_firewall.config import load_config
from ai_firewall.device_profile import DeviceProfiler, load_profiles, save_profiles
from ai_firewall.dns_parser import parse_dns_log
from ai_firewall.domains import registered_domain, tld as domain_tld
from ai_firewall.endpoint import analyze_endpoint, load_endpoint_snapshot
from ai_firewall.feedback import build_feedback_map, load_feedback
from ai_firewall.intel import ThreatIntel, update_feeds
from ai_firewall.log_integrity import append_hash_chain
from ai_firewall.online_model import load_model, save_model
from ai_firewall.policy import load_policy_state, save_policy_state
from ai_firewall.report import Report, ReportItem
from ai_firewall.statistical_model import (
    StatisticalModel,
    load_statistical_model,
    save_statistical_model,
)
from ai_firewall.trm_adapter import load_trm

MODEL_TYPES = ("statistical", "online_logistic", "trm_stub")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def analyze(
    log_path: str,
    config_path: str,
    model_path: str | None = None,
    feedback_path: str | None = None,
    endpoint_path: str | None = None,
    endpoint_baseline_path: str | None = None,
    policy_state_path: str | None = None,
    learn: bool = False,
    profiles_path: str | None = None,
    intel_dir: str | None = None,
    blocklist_path: str | None = None,
    blocklist_format: str = "abp",
    auto_block: bool = False,
) -> Report:
    config = load_config(config_path)
    if config.model_type not in MODEL_TYPES:
        raise SystemExit(f"model_type must be one of {MODEL_TYPES}, got {config.model_type!r}")
    never_block = {d.lower() for d in config.never_block}

    with Path(log_path).open(encoding="utf-8", errors="ignore") as fh:
        queries = parse_dns_log(fh)

    profiler = load_profiles(profiles_path) if profiles_path else DeviceProfiler()
    detector = AnomalyDetector(config)
    intel = ThreatIntel()
    if intel_dir and Path(intel_dir).is_dir():
        intel.load_dir(intel_dir)

    online_model = statistical_model = trm_model = None
    if config.model_type == "online_logistic":
        online_model = load_model(model_path or "", config.learning_rate)
    elif config.model_type == "statistical":
        if model_path:
            statistical_model = load_statistical_model(model_path, config.zscore_threshold)
        else:  # no saved baseline: learn one from this log alone
            statistical_model = StatisticalModel({}, {}, config.zscore_threshold)
    else:
        trm_model = load_trm(config.trm_weights, config.decision_threshold)

    feedback_map = build_feedback_map(load_feedback(feedback_path)) if feedback_path else {}
    allow_labelled = {d for (d, _), label in feedback_map.items() if label == 0}
    policy_state = load_policy_state(policy_state_path) if policy_state_path else None

    # Feedback counts ONCE per labelled domain per run, never once per query.
    learned: set[str] = set()
    now = _utcnow()

    def apply_feedback(query, features) -> None:
        if not (learn and feedback_map) or query.domain in learned:
            return
        label = feedback_map.get((query.domain, query.client))
        if label is None:
            label = feedback_map.get((query.domain, None))
        if label is None:
            return
        learned.add(query.domain)
        if online_model:
            online_model.update(_normalized(features, config), label)
        elif statistical_model:
            statistical_model.apply_feedback(query.domain, label)
        if policy_state:
            policy_state.update(query.domain, label, now)

    confirmed = set(policy_state.candidates(config.auto_promote_after)) if policy_state else set()
    items: list[ReportItem] = []
    block_domains: set[str] = set()
    summary = {"total": 0, "blocked": 0, "recommended": 0, "learned": 0, "endpoint_findings": 0}

    for query in queries:
        summary["total"] += 1
        is_new_tld = profiler.update(query.client, domain_tld(query.domain))
        flags, features = detector.score(query, is_new_tld)
        apply_feedback(query, features)

        if online_model:
            score = online_model.predict_proba(_normalized(features, config))
        elif statistical_model:
            # Score against the baseline BEFORE adding this query to it.
            score = statistical_model.score(features, query.domain)
            statistical_model.update(features)
        else:
            score = trm_model.infer(_normalized(features, config)).score

        reason = None
        protected = is_protected(query.domain, never_block) or query.domain in allow_labelled
        hit = None if protected else intel.match(query.domain)
        if hit:
            flags.intel = True
            score, decision, reason = 1.0, "block", f"threat intel: {hit[1]} lists {hit[0]}"
            block_domains.add(hit[0])
        elif not protected and (query.domain in confirmed):
            decision, reason = "block", "confirmed by your feedback"
        elif score >= config.decision_threshold and not protected:
            decision = "recommend"
            if auto_block and score >= config.auto_block_threshold:
                # Tunneling rotates subdomains, so block the parent in that case.
                target = registered_domain(query.domain) if flags.burst else query.domain
                if not is_protected(target, never_block):
                    decision, reason = "block", "auto-block: anomaly score"
                    block_domains.add(target)
        else:
            decision = "allow"

        if decision == "allow":
            continue
        summary["blocked" if decision == "block" else "recommended"] += 1
        items.append(
            ReportItem(
                timestamp=query.timestamp.isoformat(),
                client=query.client,
                domain=query.domain,
                qtype=query.qtype,
                flags=vars(flags).copy(),
                score=score,
                decision=decision,
                reason=reason,
            )
        )

    summary["learned"] = len(learned)
    if online_model and learn and model_path:
        save_model(model_path, online_model)
    if statistical_model and model_path:
        save_statistical_model(model_path, statistical_model)
    if profiles_path:
        save_profiles(profiles_path, profiler)

    endpoint_findings = None
    if endpoint_path:
        snapshot = load_endpoint_snapshot(endpoint_path)
        baseline = load_endpoint_snapshot(endpoint_baseline_path) if endpoint_baseline_path else None
        findings = analyze_endpoint(snapshot, baseline=baseline)
        endpoint_findings = [
            {"category": f.category, "severity": f.severity, "description": f.description}
            for f in findings
        ]
        summary["endpoint_findings"] = len(findings)

    policy_candidates = None
    if policy_state and policy_state_path:
        policy_state.decay(now, config.auto_promote_decay_days)
        policy_candidates = policy_state.candidates(config.auto_promote_after)
        save_policy_state(policy_state_path, policy_state)
        block_domains.update(policy_candidates)

    blocklist = None
    if blocklist_path:
        blocklist = write_blocklist(
            blocklist_path, block_domains, never_block, unblock=allow_labelled, fmt=blocklist_format
        )
        summary["blocklist_size"] = len(blocklist)

    return Report(
        items=items,
        summary=summary,
        endpoint_findings=endpoint_findings,
        policy_candidates=policy_candidates,
    )


def _normalized(features: dict[str, float], config) -> dict[str, float]:
    """Scale every feature to 0..1 so no single one (length!) dominates."""
    scaled = dict(features)
    scaled["entropy"] = min(1.0, features["entropy"] / 5.0)
    scaled["length"] = min(1.0, features["length"] / max(1, config.long_query_length))
    return scaled


def main() -> None:
    parser = argparse.ArgumentParser(description="Ghost Firewall DNS analyzer")
    parser.add_argument("--log", required=True, help="Path to Pi-hole or dnsmasq log file")
    parser.add_argument("--config", required=True, help="Path to config JSON")
    parser.add_argument("--state-dir", help="Directory for all state and outputs. Sets defaults "
                        "for --model, --policy-state, --profiles, --intel-dir, --blocklist-out, --out, --text")
    parser.add_argument("--model", help="Path to model state JSON")
    parser.add_argument("--feedback", help="Path to feedback JSON for learning")
    parser.add_argument("--endpoint", help="Path to endpoint snapshot JSON for heuristics")
    parser.add_argument("--endpoint-baseline", help="Baseline endpoint snapshot JSON for diffs")
    parser.add_argument("--policy-state", help="Path to policy state JSON for auto-promotion")
    parser.add_argument("--profiles", help="Path to device profile state JSON")
    parser.add_argument("--learn", action="store_true", help="Update model using feedback")
    parser.add_argument("--intel-dir", help="Directory of threat-intel blocklists (*.txt)")
    parser.add_argument("--update-intel", action="store_true", help="Download the feeds in config intel_feeds first")
    parser.add_argument("--blocklist-out", help="Write/merge a blocklist file for Pi-hole to enforce")
    parser.add_argument("--blocklist-format", choices=FORMATS, default="abp")
    parser.add_argument("--auto-block", action="store_true",
                        help="Also blocklist domains scoring >= auto_block_threshold without review")
    parser.add_argument("--hash-chain", help="Append a tamper-evidence link for the log to this file")
    parser.add_argument("--out", help="Output JSON report path")
    parser.add_argument("--text", help="Output text report path")
    args = parser.parse_args()

    if args.state_dir:
        state = Path(args.state_dir)
        state.mkdir(parents=True, exist_ok=True)
        defaults = {
            "model": "model.json", "policy_state": "policy.json", "profiles": "profiles.json",
            "intel_dir": "intel", "blocklist_out": "blocklist.txt", "out": "report.json",
            "text": "report.txt",
        }
        for attr, name in defaults.items():
            if getattr(args, attr) is None:
                setattr(args, attr, str(state / name))

    if args.update_intel:
        if not args.intel_dir:
            parser.error("--update-intel needs --intel-dir or --state-dir")
        for name, status in update_feeds(load_config(args.config).intel_feeds, args.intel_dir).items():
            print(f"intel feed {name}: {status}")

    report = analyze(
        args.log,
        args.config,
        model_path=args.model,
        feedback_path=args.feedback,
        endpoint_path=args.endpoint,
        endpoint_baseline_path=args.endpoint_baseline,
        policy_state_path=args.policy_state,
        learn=args.learn,
        profiles_path=args.profiles,
        intel_dir=args.intel_dir,
        blocklist_path=args.blocklist_out,
        blocklist_format=args.blocklist_format,
        auto_block=args.auto_block,
    )

    if args.hash_chain:
        append_hash_chain(args.log, args.hash_chain)
    if args.out:
        Path(args.out).write_text(report.to_json(), encoding="utf-8")
    if args.text:
        Path(args.text).write_text(report.to_text(), encoding="utf-8")
    print(", ".join(f"{k}={v}" for k, v in report.summary.items()))


if __name__ == "__main__":
    main()
