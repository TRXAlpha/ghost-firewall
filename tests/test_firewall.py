import base64
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ai_firewall import log_integrity
from ai_firewall.anomaly import name_entropy
from ai_firewall.blocklist import is_protected, write_blocklist
from ai_firewall.cli import analyze
from ai_firewall.dns_parser import _parse_timestamp, parse_dns_log
from ai_firewall.domains import parents, registered_domain, subdomain
from ai_firewall.endpoint import _is_private_ip, analyze_endpoint
from ai_firewall.feedback import _normalize_label
from ai_firewall.intel import ThreatIntel, parse_blocklist_line

CONFIG = str(ROOT / "config" / "example_config.json")
BENIGN = ["google.com", "www.github.com", "api.spotify.com", "outlook.office365.com",
          "time.windows.com", "cdn.jsdelivr.net", "mail.proton.me", "safebrowsing.googleapis.com"]


def make_log(path, tunnel=True, extra=()):
    lines = []
    for i in range(1500):
        lines.append(f"Nov 11 10:{i // 60 % 60:02d}:{i % 60:02d} dnsmasq[1]: "
                     f"query[A] {BENIGN[i % len(BENIGN)]} from 192.168.1.{10 + i % 3}")
    if tunnel:
        for i in range(100):
            sub = base64.b32encode(os.urandom(30)).decode().lower().strip("=")
            lines.insert(600 + i * 3, f"Nov 11 10:20:{i % 30:02d} dnsmasq[1]: "
                         f"query[TXT] {sub}.t.evil-tunnel.xyz from 192.168.1.50")
    lines.extend(extra)
    Path(path).write_text("\n".join(lines), encoding="utf-8")


class ParserTests(unittest.TestCase):
    def test_pihole_and_syslog_formats(self):
        lines = [
            "Nov 11 10:00:01 dnsmasq[1234]: query[A] Google.COM. from 192.168.1.10",
            "Nov 11 10:00:02 pihole dnsmasq[1234]: query[AAAA] a.example.org from fe80::1",
            "Nov 11 10:00:03 dnsmasq[1234]: 77 192.168.1.9/5353 query[TXT] x.example.net from 192.168.1.9",
            "Nov 11 10:00:04 dnsmasq[1234]: reply google.com is 1.2.3.4",
        ]
        queries = parse_dns_log(lines)
        self.assertEqual([q.domain for q in queries], ["google.com", "a.example.org", "x.example.net"])
        self.assertEqual(queries[1].client, "fe80::1")

    def test_year_rollover(self):
        now = datetime(2026, 1, 2, 9, 0, 0)
        self.assertEqual(_parse_timestamp("Dec 31 23:59:59", now).year, 2025)
        self.assertEqual(_parse_timestamp("Jan  1 08:00:00", now).year, 2026)


class DomainTests(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(registered_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(registered_domain("a.b.example.com"), "example.com")
        self.assertEqual(subdomain("a.b.example.com"), "a.b")
        self.assertEqual(list(parents("a.b.c")), ["a.b.c", "b.c"])

    def test_entropy_ignores_ordinary_long_names(self):
        self.assertLess(name_entropy("outlook.office365.com"), 3.5)
        self.assertLess(name_entropy("safebrowsing.googleapis.com"), 3.5)
        self.assertGreater(name_entropy("mzxw6ytboi4dqnrrgezdgnbvgy3tqojq.evil.xyz"), 3.5)


class FeedbackTests(unittest.TestCase):
    def test_unknown_labels_are_not_allow(self):
        self.assertIsNone(_normalize_label("review"))
        self.assertIsNone(_normalize_label("malware"))
        self.assertEqual(_normalize_label(" Block "), 1)
        self.assertEqual(_normalize_label("allow"), 0)


class IntelTests(unittest.TestCase):
    def test_formats_and_parent_match(self):
        for line, want in [("0.0.0.0 bad.example", "bad.example"), ("||bad.example^", "bad.example"),
                           ("*.bad.example", "bad.example"), ("bad.example # note", "bad.example"),
                           ("# comment", None), ("127.0.0.1 localhost", None), ("<html>", None)]:
            self.assertEqual(parse_blocklist_line(line), want, line)
        intel = ThreatIntel()
        intel.add_lines(["bad.example"], "feed")
        self.assertEqual(intel.match("c2.bad.example"), ("bad.example", "feed"))
        self.assertIsNone(intel.match("notbad.example"))


class BlocklistTests(unittest.TestCase):
    def test_protection_and_merge(self):
        never = {"google.com", "storage.googleapis.com"}
        self.assertTrue(is_protected("evil.google.com", never))
        self.assertTrue(is_protected("googleapis.com", never))
        self.assertFalse(is_protected("evil.xyz", never))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bl.txt")
            write_blocklist(path, {"evil.xyz", "google.com"}, never)
            final = write_blocklist(path, {"bad.top", "oops.com"}, never, unblock={"oops.com"})
            self.assertEqual(final, ["bad.top", "evil.xyz"])
            self.assertIn("||evil.xyz^", Path(path).read_text())


class EndpointTests(unittest.TestCase):
    def test_private_ips_and_missing_signature(self):
        for ip in ["::", "fe80::1", "fd00::5", "169.254.1.1", "100.64.0.1", "10.0.0.1", ""]:
            self.assertTrue(_is_private_ip(ip), ip)
        self.assertFalse(_is_private_ip("8.8.8.8"))
        snapshot = {
            "tcp_connections": [
                {"remote_address": "8.8.8.8", "process_name": "System", "signature_status": None},
                {"remote_address": "8.8.8.8", "process_name": "x", "signature_status": "NotSigned"},
            ],
            "processes": [{"name": "Code.exe", "path": "C:\\Users\\me\\AppData\\Code.exe",
                           "signature_status": None}],
        }
        findings = analyze_endpoint(snapshot)
        self.assertEqual([f.category for f in findings], ["network"])


class IntegrityTests(unittest.TestCase):
    def test_chain(self):
        self.assertNotEqual(log_integrity.hash_log_lines(["ab", "c"]),
                            log_integrity.hash_log_lines(["a", "bc"]))
        with tempfile.TemporaryDirectory() as tmp:
            log, chain = os.path.join(tmp, "l"), os.path.join(tmp, "c")
            Path(log).write_text("one\n")
            log_integrity.append_hash_chain(log, chain)
            Path(log).write_text("two\n")
            log_integrity.append_hash_chain(log, chain)
            self.assertTrue(log_integrity.verify_hash_chain(chain))
            lines = Path(chain).read_text().splitlines()
            Path(chain).write_text(lines[0].replace(lines[0][-1], "0" if lines[0][-1] != "0" else "1") + "\n" + lines[1] + "\n")
            self.assertFalse(log_integrity.verify_hash_chain(chain))


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.p = lambda name: os.path.join(self.tmp.name, name)

    def test_clean_log_is_quiet(self):
        make_log(self.p("log"), tunnel=False)
        report = analyze(self.p("log"), CONFIG, model_path=self.p("m.json"))
        self.assertEqual(report.summary["total"], 1500)
        self.assertEqual(report.summary["recommended"], 0)

    def test_tunnel_detected_and_auto_blocked_at_parent(self):
        make_log(self.p("log"))
        report = analyze(self.p("log"), CONFIG, model_path=self.p("m.json"),
                         blocklist_path=self.p("bl.txt"), auto_block=True)
        flagged = [i for i in report.items if "evil-tunnel" in i.domain]
        false_pos = [i for i in report.items if "evil-tunnel" not in i.domain]
        self.assertGreaterEqual(len(flagged), 85)
        self.assertEqual(false_pos, [])
        self.assertTrue(any(i.flags["burst"] for i in flagged))
        self.assertIn("||evil-tunnel.xyz^", Path(self.p("bl.txt")).read_text())

    def test_no_auto_block_without_flag(self):
        make_log(self.p("log"))
        report = analyze(self.p("log"), CONFIG, blocklist_path=self.p("bl.txt"))
        self.assertEqual(report.summary["blocked"], 0)
        self.assertNotIn("||", Path(self.p("bl.txt")).read_text())

    def test_intel_hit_blocks_and_never_block_wins(self):
        os.mkdir(self.p("intel"))
        Path(self.p("intel/feed.txt")).write_text("malware-c2.top\ngoogle.com\n")
        make_log(self.p("log"), tunnel=False, extra=[
            "Nov 11 11:00:00 dnsmasq[1]: query[A] cdn.malware-c2.top from 192.168.1.10"])
        report = analyze(self.p("log"), CONFIG, intel_dir=self.p("intel"),
                         blocklist_path=self.p("bl.txt"))
        self.assertEqual([i.domain for i in report.items], ["cdn.malware-c2.top"])
        self.assertEqual(report.items[0].decision, "block")
        self.assertEqual(Path(self.p("bl.txt")).read_text().splitlines()[1:], ["||malware-c2.top^"])

    def test_one_label_is_one_confirmation(self):
        make_log(self.p("log"), tunnel=False, extra=[
            f"Nov 11 11:00:{i:02d} dnsmasq[1]: query[A] shady.example from 192.168.1.10" for i in range(40)])
        Path(self.p("fb.json")).write_text(json.dumps({"labels": [
            {"domain": "shady.example", "label": "block"},
            {"domain": "api.spotify.com", "label": "review"}]}))
        kwargs = dict(model_path=self.p("m.json"), feedback_path=self.p("fb.json"), learn=True,
                      policy_state_path=self.p("p.json"), blocklist_path=self.p("bl.txt"))
        report = analyze(self.p("log"), CONFIG, **kwargs)
        policy = json.loads(Path(self.p("p.json")).read_text())
        self.assertEqual(policy["confirmations"], {"shady.example": 1})
        self.assertEqual(report.summary["learned"], 1)
        self.assertEqual(report.policy_candidates, [])
        analyze(self.p("log"), CONFIG, **kwargs)
        report = analyze(self.p("log"), CONFIG, **kwargs)
        self.assertEqual(report.policy_candidates, ["shady.example"])
        self.assertIn("||shady.example^", Path(self.p("bl.txt")).read_text())

    def test_all_model_types_run_and_stay_quiet_on_clean_traffic(self):
        make_log(self.p("log"), tunnel=False)
        base = json.loads(Path(CONFIG).read_text())
        for model_type in ("online_logistic", "trm_stub"):
            base["model_type"] = model_type
            Path(self.p("c.json")).write_text(json.dumps(base))
            report = analyze(self.p("log"), self.p("c.json"))
            self.assertEqual(report.summary["recommended"], 0, model_type)


if __name__ == "__main__":
    unittest.main()
