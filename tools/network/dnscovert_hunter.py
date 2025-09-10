#!/usr/bin/env python3
"""
DNSCovert Hunter: Encrypted DNS Covert Channel Detector

Ethical and legal notice:
- This tool is intended for authorized defensive security monitoring and testing only.
- Use only on networks and systems you are explicitly authorized to monitor.
- It operates passively and does not decrypt payloads; it stores only flow-level features and anonymized host metadata to preserve privacy.

Overview:
- Detects covert data exfiltration over DoH/DoT/ODoH by modeling resolver fingerprints, entropy and subdomain length distributions, flow timing, and JA3/JA4 deltas.
- Correlates SNI/ECH metadata and CDN domain-fronting anomalies with enterprise allowlists.
- Supports strict resolver allowlists and baseline modeling to minimize false positives.
- Rate-limits alerts and provides explainable feature attributions.
- Signs flow summaries and model/version metadata; supports reproducible detection reports with integrity verification via HMAC.

Note:
- Input must be flow metadata from passive sources. No payload decryption is needed or performed.
- For privacy, raw host identifiers and query names are not stored; they are anonymized or reduced to summary statistics immediately.
"""

from __future__ import annotations

import time
import hmac
import hashlib
import json
from dataclasses import dataclass, field
from collections import defaultdict, deque
from statistics import mean, pstdev
from typing import Any, Deque, Dict, List, Optional, Tuple


VERSION = "1.0.0"


def _now() -> float:
    return time.time()


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hmac_hex(key: bytes, data: str) -> str:
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _safe_mean(values: List[float]) -> float:
    return float(mean(values)) if values else 0.0


def _safe_pstdev(values: List[float]) -> float:
    return float(pstdev(values)) if len(values) > 1 else 0.0


def _shannon_entropy(strings: List[str]) -> float:
    """
    Shannon entropy in bits per character computed across concatenated strings.

    Note: The strings are not stored. We immediately aggregate and drop inputs.
    """
    if not strings:
        return 0.0
    concat = "".join(strings)
    if not concat:
        return 0.0
    freq: Dict[str, int] = defaultdict(int)
    for ch in concat:
        freq[ch] += 1
    length = len(concat)
    import math

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log(p, 2)
    return entropy


def _lengths(strings: List[str]) -> List[int]:
    return [len(s) for s in strings if isinstance(s, str)]


@dataclass
class ResolverBaseline:
    count: int = 0
    avg_entropy_sum: float = 0.0
    sub_len_mean_sum: float = 0.0
    method_post_ratio_sum: float = 0.0

    def update(self, avg_entropy: float, sub_len_mean: float, method_post_ratio: float) -> None:
        self.count += 1
        self.avg_entropy_sum += avg_entropy
        self.sub_len_mean_sum += sub_len_mean
        self.method_post_ratio_sum += method_post_ratio

    def means(self) -> Dict[str, float]:
        if self.count == 0:
            return {"avg_entropy": 0.0, "sub_len_mean": 0.0, "method_post_ratio": 0.0}
        return {
            "avg_entropy": self.avg_entropy_sum / self.count,
            "sub_len_mean": self.sub_len_mean_sum / self.count,
            "method_post_ratio": self.method_post_ratio_sum / self.count,
        }


@dataclass
class Config:
    anonymization_salt: bytes = field(default_factory=lambda: hashlib.sha256(b"default-salt").digest())
    signing_key: bytes = field(default_factory=lambda: hashlib.sha256(b"default-signing-key").digest())
    resolver_allowlist: set = field(default_factory=set)  # allowed resolver IDs (IP/SNI/name)
    approved_fingerprints: Dict[str, set] = field(default_factory=dict)  # resolver_id -> set of (ja3, ja4)
    cdn_allowlist: set = field(default_factory=set)  # SNI of known CDN front domains
    # detection thresholds
    high_entropy_threshold: float = 4.2  # bits per char
    subdomain_length_mean_threshold: float = 30.0
    sustained_flow_window_seconds: int = 300
    sustained_flow_min_flows: int = 5
    post_ratio_threshold: float = 0.6  # proportion POST to consider suspicious for DoH
    # rate limiting
    alert_rate_limit_per_key_per_minute: int = 5
    # toggles
    strict_allowlist: bool = True
    enable_ja_delta_detection: bool = True

    # metadata
    version: str = VERSION


class DNSCovertHunter:
    def __init__(self, config: Optional[Config] = None) -> None:
        self.cfg = config if config is not None else Config()

        # Privacy-preserving states
        # key: (anon_src, resolver_id) -> deque of flow summaries
        self._flows_by_key: Dict[Tuple[str, str], Deque[Dict[str, Any]]] = defaultdict(deque)
        # sessions by 3-tuple to detect JA3/JA4 shifts mid-session
        self._sessions: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
        # allowlist caches (normalized)
        self._allowed_resolvers = set(self.cfg.resolver_allowlist)
        self._cdn_allowlist = set(self.cfg.cdn_allowlist)

        # baseline
        self._baseline_mode: bool = False
        self._baseline: Dict[Tuple[str, str, str], ResolverBaseline] = {}  # (resolver_id, ja3, ja4) -> baseline

        # alerts and rate limiting
        self._alerts: List[Dict[str, Any]] = []
        self._alert_times: Dict[str, Deque[float]] = defaultdict(deque)

        # privacy control: do not store raw subdomains; only summary
        # ethics disclaimer shown in logs only on init
        self._log_warn("DNSCovert Hunter initialized. Authorized passive monitoring only. No payload decryption performed.")

    # Public API

    def start_baseline(self) -> None:
        self._baseline_mode = True
        self._log_info("Baseline learning mode started.")

    def end_baseline(self) -> None:
        self._baseline_mode = False
        self._log_info("Baseline learning mode ended. Baseline frozen.")

    def set_resolver_allowlist(self, resolvers: List[str]) -> None:
        self._allowed_resolvers = set(resolvers)

    def set_cdn_allowlist(self, cdn_snis: List[str]) -> None:
        self._cdn_allowlist = set(cdn_snis)

    def set_approved_fingerprints(self, mapping: Dict[str, List[Tuple[str, str]]]) -> None:
        self.cfg.approved_fingerprints = {k: set(v) for k, v in mapping.items()}

    def add_flow(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Ingest a single passive flow observation and optionally return an alert dict.
        Expected flow keys (best-effort, optional tolerated):
        - timestamp: float
        - src_ip, src_port, dst_ip, dst_port, protocol
        - is_doh, is_dot, is_odoh: bool
        - method: 'GET'|'POST'|None (inferred heuristically by sensor; not decrypted)
        - sni: str|None, ech: bool, alpn: str|None
        - ja3, ja4: str|None
        - bytes_out, bytes_in, packet_count_out, packet_count_in: int
        - iat_ms: list[float] (inter-arrival times) or None
        - queried_subdomains: list[str] sample subdomain strings from metadata; not stored
        - resolver_name: str optional identity mapping (from IP intel/cert metadata)
        - cdn_sni: bool optional override to treat SNI as CDN front
        """
        try:
            features = self._extract_and_summarize(flow)
        except Exception as e:
            self._log_error(f"Flow parse error: {e}")
            return None

        if self._baseline_mode:
            self._update_baseline(features)
            return None

        # Update windowed store for sustained analysis
        self._update_window(features)

        # Run immediate detection rules
        alert = self._detect_domain_fronting(features)
        if alert and self._emit_alert(alert):
            return alert

        # Run sustained covert channel detection
        alert2 = self._detect_sustained_covert(features)
        if alert2 and self._emit_alert(alert2):
            return alert2

        return None

    def get_alerts(self) -> List[Dict[str, Any]]:
        return list(self._alerts)

    def clear_alerts(self) -> None:
        self._alerts.clear()
        self._alert_times.clear()

    def generate_report(self, include_flows: bool = True) -> str:
        """
        Generate a deterministic JSON report containing model metadata and alerts.
        Returns a JSON string with top-level signature.
        """
        report = {
            "tool": "DNSCovert Hunter",
            "version": self.cfg.version,
            "generated_at": int(_now()),
            "model_metadata": {
                "high_entropy_threshold": self.cfg.high_entropy_threshold,
                "subdomain_length_mean_threshold": self.cfg.subdomain_length_mean_threshold,
                "post_ratio_threshold": self.cfg.post_ratio_threshold,
                "sustained_flow_window_seconds": self.cfg.sustained_flow_window_seconds,
                "sustained_flow_min_flows": self.cfg.sustained_flow_min_flows,
                "strict_allowlist": self.cfg.strict_allowlist,
                "enable_ja_delta_detection": self.cfg.enable_ja_delta_detection,
            },
            "alerts": [],
        }
        for a in self._alerts:
            entry = {
                "id": a["id"],
                "time": a["time"],
                "severity": a["severity"],
                "type": a["type"],
                "anonymized_src": a["anonymized_src"],
                "resolver_id": a["resolver_id"],
                "explain": a["explain"],
            }
            if include_flows:
                entry["flows"] = a.get("flows", [])
                # Sign each flow summary deterministically
                for f in entry["flows"]:
                    f["flow_signature"] = _hmac_hex(self.cfg.signing_key, _canonical_json(f))
            entry["alert_signature"] = _hmac_hex(self.cfg.signing_key, _canonical_json(entry))
            report["alerts"].append(entry)

        # Attach signature for the whole report (including embedded alert signatures)
        report_signature = _hmac_hex(self.cfg.signing_key, _canonical_json(report))
        report["signature"] = report_signature
        return _canonical_json(report)

    def verify_report(self, report_json: str) -> bool:
        """
        Verify integrity of a report generated by this instance with the same signing key.
        """
        try:
            report = json.loads(report_json)
            sig = report.get("signature", "")
            # Temporarily remove signature to recompute
            tmp = dict(report)
            tmp.pop("signature", None)
            expected = _hmac_hex(self.cfg.signing_key, _canonical_json(tmp))
            return hmac.compare_digest(sig, expected)
        except Exception:
            return False

    # Internal

    def _extract_and_summarize(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        ts = float(flow.get("timestamp", _now()))
        src_ip = str(flow.get("src_ip", "0.0.0.0"))
        dst_ip = str(flow.get("dst_ip", "0.0.0.0"))
        dst_port = int(flow.get("dst_port", 0))
        protocol = str(flow.get("protocol", "tcp")).lower()
        is_doh = bool(flow.get("is_doh", False))
        is_dot = bool(flow.get("is_dot", False))
        is_odoh = bool(flow.get("is_odoh", False))
        method = flow.get("method")
        sni = flow.get("sni")
        ech = bool(flow.get("ech", False))
        alpn = flow.get("alpn")
        ja3 = flow.get("ja3")
        ja4 = flow.get("ja4")
        bytes_out = int(flow.get("bytes_out", 0))
        bytes_in = int(flow.get("bytes_in", 0))
        pkt_out = int(flow.get("packet_count_out", 0))
        pkt_in = int(flow.get("packet_count_in", 0))
        iat_ms = flow.get("iat_ms") or []
        queried_subdomains: List[str] = list(flow.get("queried_subdomains") or [])
        resolver_name = flow.get("resolver_name")
        cdn_sni_flag = bool(flow.get("cdn_sni", False))

        # Compute entropy & subdomain length stats without storing raw subdomains
        sub_len = _lengths(queried_subdomains)
        entropy = _shannon_entropy(queried_subdomains) if queried_subdomains else 0.0
        sub_len_mean = _safe_mean([float(x) for x in sub_len])
        sub_len_p90 = 0.0
        if sub_len:
            sorted_len = sorted(sub_len)
            idx = min(len(sorted_len) - 1, int(0.9 * len(sorted_len)))
            sub_len_p90 = float(sorted_len[idx])
        # Drop queried_subdomains immediately to preserve privacy
        queried_subdomains = []

        # Resolver identity and allowlist determination
        resolver_id = self._resolver_identity(resolver_name, sni, dst_ip)
        resolver_approved = self._is_resolver_approved(resolver_id)

        # JA3/JA4 delta detection within session
        anon_src = self._anon(src_ip)
        anon_dst = self._anon(dst_ip)
        sess_key = (anon_src, anon_dst, dst_port)
        ja_delta = False
        last_sess = self._sessions.get(sess_key)
        if self.cfg.enable_ja_delta_detection:
            if last_sess:
                if (ja3 and last_sess.get("ja3") and ja3 != last_sess["ja3"]) or (ja4 and last_sess.get("ja4") and ja4 != last_sess["ja4"]):
                    ja_delta = True
                # Update last seen fingerprints
                if ja3:
                    last_sess["ja3"] = ja3
                if ja4:
                    last_sess["ja4"] = ja4
                last_sess["last_seen"] = ts
            else:
                self._sessions[sess_key] = {"ja3": ja3, "ja4": ja4, "start": ts, "last_seen": ts}
        # Expire old sessions (simple)
        self._expire_sessions(ts)

        doh_like = is_doh or is_odoh or (is_dot and protocol == "tcp")
        post = (method or "").upper() == "POST"
        get = (method or "").upper() == "GET"

        # Flow timing summaries
        iat_mean = _safe_mean([float(x) for x in iat_ms]) if iat_ms else 0.0
        iat_std = _safe_pstdev([float(x) for x in iat_ms]) if iat_ms else 0.0

        # Heuristic CDN front SNI
        sni_lower = (sni or "").lower()
        cdn_sni = cdn_sni_flag or (sni_lower in self._cdn_allowlist)

        # Approved fingerprints for resolver
        fp_approved = False
        if resolver_id and self.cfg.approved_fingerprints.get(resolver_id):
            fp_approved = (ja3, ja4) in self.cfg.approved_fingerprints.get(resolver_id, set())

        # Summarize the flow
        summary = {
            "time": ts,
            "anonymized_src": anon_src,
            "anonymized_dst": anon_dst,
            "dst_port": dst_port,
            "protocol": protocol,
            "is_doh": bool(is_doh),
            "is_dot": bool(is_dot),
            "is_odoh": bool(is_odoh),
            "doh_like": bool(doh_like),
            "method_post": bool(post),
            "method_get": bool(get),
            "sni_present": bool(bool(sni) and not ech),
            "ech_present": bool(ech),
            "alpn": alpn or "",
            "ja3": ja3 or "",
            "ja4": ja4 or "",
            "ja_delta": bool(ja_delta),
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "pkt_out": pkt_out,
            "pkt_in": pkt_in,
            "iat_mean_ms": iat_mean,
            "iat_std_ms": iat_std,
            "entropy": float(entropy),
            "subdomain_len_mean": float(sub_len_mean),
            "subdomain_len_p90": float(sub_len_p90),
            "resolver_id": resolver_id,
            "resolver_approved": bool(resolver_approved),
            "fingerprint_approved": bool(fp_approved),
            "cdn_sni": bool(cdn_sni),
        }
        # For reproducibility and integrity: attach flow summary signature
        summary["summary_signature"] = _hmac_hex(self.cfg.signing_key, _canonical_json(summary))
        return summary

    def _resolver_identity(self, resolver_name: Optional[str], sni: Optional[str], dst_ip: str) -> str:
        # Priority: resolver_name if provided by passive intel, else SNI hostname, else dst IP
        if resolver_name:
            return str(resolver_name).lower()
        if sni:
            return str(sni).lower()
        return str(dst_ip)

    def _is_resolver_approved(self, resolver_id: str) -> bool:
        if not self.cfg.strict_allowlist:
            # In non-strict mode, if allowlist empty, treat none as approved
            return resolver_id in self._allowed_resolvers if self._allowed_resolvers else False
        return resolver_id in self._allowed_resolvers

    def _update_baseline(self, features: Dict[str, Any]) -> None:
        if not (features["doh_like"] or features["is_dot"]):
            return
        key = (features["resolver_id"], features["ja3"], features["ja4"])
        base = self._baseline.get(key)
        if not base:
            base = ResolverBaseline()
            self._baseline[key] = base
        # For baseline, accumulate averages per flow considering DoH-like flows only
        base.update(
            avg_entropy=features["entropy"],
            sub_len_mean=features["subdomain_len_mean"],
            method_post_ratio=1.0 if features["method_post"] else 0.0,
        )

    def _update_window(self, features: Dict[str, Any]) -> None:
        key = (features["anonymized_src"], features["resolver_id"])
        dq = self._flows_by_key[key]
        dq.append(features)
        # expire older than window
        cutoff = features["time"] - self.cfg.sustained_flow_window_seconds
        while dq and dq[0]["time"] < cutoff:
            dq.popleft()

    def _detect_sustained_covert(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not features["doh_like"]:
            return None

        key = (features["anonymized_src"], features["resolver_id"])
        window = self._flows_by_key.get(key, deque())
        if len(window) < self.cfg.sustained_flow_min_flows:
            return None

        # Compute windowed stats
        entropies = [f["entropy"] for f in window if f["entropy"] >= 0.0]
        sub_means = [f["subdomain_len_mean"] for f in window]
        posts = [1.0 if f["method_post"] else 0.0 for f in window]
        post_ratio = _safe_mean(posts)
        avg_entropy = _safe_mean(entropies)
        avg_sub_mean = _safe_mean(sub_means)

        resolver_approved = window[-1]["resolver_approved"]
        fingerprint_approved = window[-1]["fingerprint_approved"]

        # If resolver is approved and fingerprints match baseline/approved, suppress unless extreme anomalies
        if resolver_approved and fingerprint_approved:
            # Compare to learned baseline if available, with tolerance
            base_key = (window[-1]["resolver_id"], window[-1]["ja3"], window[-1]["ja4"])
            baseline_means = self._baseline.get(base_key).means() if self._baseline.get(base_key) else None
            if baseline_means:
                ent_ok = avg_entropy <= (baseline_means["avg_entropy"] + 0.5)
                len_ok = avg_sub_mean <= (baseline_means["sub_len_mean"] + 10.0)
                post_ok = post_ratio <= max(0.8, baseline_means["method_post_ratio"] + 0.2)
                if ent_ok and len_ok and post_ok:
                    return None

        # Covert channel suspicion to non-approved resolvers or anomalous against baseline
        reasons: Dict[str, Any] = {
            "avg_entropy": round(avg_entropy, 3),
            "entropy_threshold": self.cfg.high_entropy_threshold,
            "avg_subdomain_len": round(avg_sub_mean, 2),
            "subdomain_len_threshold": self.cfg.subdomain_length_mean_threshold,
            "post_ratio": round(post_ratio, 3),
            "post_ratio_threshold": self.cfg.post_ratio_threshold,
            "resolver_approved": resolver_approved,
            "fingerprint_approved": fingerprint_approved,
        }

        suspicious = (
            (avg_entropy >= self.cfg.high_entropy_threshold)
            and (avg_sub_mean >= self.cfg.subdomain_length_mean_threshold)
            and (post_ratio >= self.cfg.post_ratio_threshold)
        )

        if suspicious and (not resolver_approved or not fingerprint_approved):
            return self._build_alert(
                alert_type="covert_channel",
                severity="high",
                features=features,
                reasons=reasons,
                flows=list(window)[-self.cfg.sustained_flow_min_flows :],
            )

        # If resolver is approved but extreme anomaly beyond baseline, lower severity
        if suspicious and resolver_approved and not fingerprint_approved:
            return self._build_alert(
                alert_type="covert_channel_anomalous_baseline",
                severity="medium",
                features=features,
                reasons=reasons,
                flows=list(window)[-self.cfg.sustained_flow_min_flows :],
            )

        return None

    def _detect_domain_fronting(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not features["doh_like"]:
            return None

        # Heuristics:
        # - SNI is a CDN front (or ECH hides SNI but flagged as CDN by metadata)
        # - Resolver identity suggests a different resolver (e.g., known DoH resolver by IP/name)
        # - JA3/JA4 fingerprint shifts mid-session (ja_delta)
        cdn_front = bool(features["cdn_sni"] or (features["ech_present"] and features["sni_present"] is False))
        resolver_mismatch = (features["resolver_id"] not in self._cdn_allowlist) and (not features["resolver_approved"])
        ja_delta = features["ja_delta"]

        if cdn_front and resolver_mismatch and ja_delta:
            reasons = {
                "cdn_front_sni": bool(features["cdn_sni"]),
                "ech_present": bool(features["ech_present"]),
                "resolver_id": features["resolver_id"],
                "resolver_approved": bool(features["resolver_approved"]),
                "ja3": features["ja3"],
                "ja4": features["ja4"],
                "ja_delta": bool(ja_delta),
            }
            return self._build_alert(
                alert_type="domain_fronted_doh",
                severity="high",
                features=features,
                reasons=reasons,
                flows=[features],
            )
        return None

    def _build_alert(
        self,
        alert_type: str,
        severity: str,
        features: Dict[str, Any],
        reasons: Dict[str, Any],
        flows: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        alert = {
            "id": self._alert_id(features, alert_type),
            "type": alert_type,
            "time": int(features["time"]),
            "severity": severity,
            "anonymized_src": features["anonymized_src"],
            "resolver_id": features["resolver_id"],
            "explain": reasons,
            "flows": [self._sanitize_flow_for_report(f) for f in flows],
        }
        return alert

    def _emit_alert(self, alert: Dict[str, Any]) -> bool:
        key = alert["id"]
        now = float(alert["time"])
        # rate limit per minute
        dq = self._alert_times[key]
        dq.append(now)
        cutoff = now - 60.0
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) > self.cfg.alert_rate_limit_per_key_per_minute:
            # Suppress this alert due to rate limiting
            return False
        # Attach signature for deterministic integrity
        alert["alert_signature"] = _hmac_hex(self.cfg.signing_key, _canonical_json(alert))
        self._alerts.append(alert)
        return True

    def _alert_id(self, features: Dict[str, Any], alert_type: str) -> str:
        base = {
            "src": features["anonymized_src"],
            "resolver": features["resolver_id"],
            "type": alert_type,
            "version": self.cfg.version,
        }
        return _sha256_hex(_canonical_json(base))[:24]

    def _sanitize_flow_for_report(self, f: Dict[str, Any]) -> Dict[str, Any]:
        keys = [
            "time",
            "anonymized_src",
            "anonymized_dst",
            "dst_port",
            "protocol",
            "is_doh",
            "is_dot",
            "is_odoh",
            "doh_like",
            "method_post",
            "method_get",
            "sni_present",
            "ech_present",
            "alpn",
            "ja3",
            "ja4",
            "ja_delta",
            "bytes_out",
            "bytes_in",
            "pkt_out",
            "pkt_in",
            "iat_mean_ms",
            "iat_std_ms",
            "entropy",
            "subdomain_len_mean",
            "subdomain_len_p90",
            "resolver_id",
            "resolver_approved",
            "fingerprint_approved",
            "cdn_sni",
            "summary_signature",
        ]
        return {k: f.get(k) for k in keys}

    def _expire_sessions(self, now_ts: float) -> None:
        expire_cutoff = now_ts - max(2 * self.cfg.sustained_flow_window_seconds, 600)
        to_del = []
        for k, v in self._sessions.items():
            if v.get("last_seen", 0) < expire_cutoff:
                to_del.append(k)
        for k in to_del:
            self._sessions.pop(k, None)

    def _anon(self, value: str) -> str:
        try:
            return hmac.new(self.cfg.anonymization_salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
        except Exception:
            # fallback to hash
            return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]

    # Logging helpers (minimal to keep single-file module)

    def _log_info(self, msg: str) -> None:
        print(f"[INFO] {time.strftime('%Y-%m-%d %H:%M:%S')} DNSCovertHunter: {msg}")

    def _log_warn(self, msg: str) -> None:
        print(f"[WARN] {time.strftime('%Y-%m-%d %H:%M:%S')} DNSCovertHunter: {msg}")

    def _log_error(self, msg: str) -> None:
        print(f"[ERROR] {time.strftime('%Y-%m-%d %H:%M:%S')} DNSCovertHunter: {msg}")


# Optional simple demonstration if run directly (no network capture; safe and ethical)
if __name__ == "__main__":
    hunter = DNSCovertHunter()

    # Configure allowlists (example)
    hunter.set_resolver_allowlist(["dns.google", "cloudflare-dns.com"])
    hunter.set_cdn_allowlist(["cdn.example.com", "cdn.cloudflare.com"])
    hunter.set_approved_fingerprints(
        {
            "dns.google": [("ja3_google", "ja4_chrome")],
            "cloudflare-dns.com": [("ja3_cf", "ja4_firefox")],
        }
    )

    # Learn baseline (simulated)
    hunter.start_baseline()
    now = _now()
    for i in range(10):
        hunter.add_flow(
            {
                "timestamp": now + i,
                "src_ip": "10.0.0.2",
                "dst_ip": "8.8.8.8",
                "dst_port": 443,
                "protocol": "tcp",
                "is_doh": True,
                "method": "GET",
                "sni": "dns.google",
                "ech": False,
                "alpn": "h2",
                "ja3": "ja3_google",
                "ja4": "ja4_chrome",
                "bytes_out": 500,
                "bytes_in": 1200,
                "packet_count_out": 5,
                "packet_count_in": 6,
                "iat_ms": [10, 12, 9, 11],
                "queried_subdomains": ["www", "mail", "api"],
                "resolver_name": "dns.google",
            }
        )
    hunter.end_baseline()

    # Simulate suspicious sustained high-entropy POST DoH to non-approved resolver
    for i in range(6):
        hunter.add_flow(
            {
                "timestamp": now + 100 + i,
                "src_ip": "10.0.0.3",
                "dst_ip": "203.0.113.50",
                "dst_port": 443,
                "protocol": "tcp",
                "is_doh": True,
                "method": "POST",
                "sni": "unknown-resolver.local",
                "ech": False,
                "alpn": "h2",
                "ja3": "ja3_tool",
                "ja4": "ja4_tool",
                "bytes_out": 2500,
                "bytes_in": 2600,
                "packet_count_out": 8,
                "packet_count_in": 8,
                "iat_ms": [5, 6, 7, 5, 5],
                "queried_subdomains": ["x" * 48, "a9F2kLmN3pQrStUvWxYz1234", "B" * 60],
                "resolver_name": "unknown-resolver.local",
            }
        )

    # Simulate domain-fronted DoH via CDN with JA3/JA4 shift
    hunter.add_flow(
        {
            "timestamp": now + 200,
            "src_ip": "10.0.0.4",
            "dst_ip": "198.51.100.20",
            "dst_port": 443,
            "protocol": "tcp",
            "is_doh": True,
            "method": "POST",
            "sni": "cdn.example.com",
            "ech": False,
            "alpn": "h2",
            "ja3": "ja3_old",
            "ja4": "ja4_old",
            "bytes_out": 900,
            "bytes_in": 1000,
            "packet_count_out": 6,
            "packet_count_in": 6,
            "iat_ms": [10, 10, 10],
            "queried_subdomains": ["test"],
            "resolver_name": "evil-resolver.example",  # mismatch with CDN SNI
            "cdn_sni": True,
        }
    )
    hunter.add_flow(
        {
            "timestamp": now + 201,
            "src_ip": "10.0.0.4",
            "dst_ip": "198.51.100.20",
            "dst_port": 443,
            "protocol": "tcp",
            "is_doh": True,
            "method": "POST",
            "sni": "cdn.example.com",
            "ech": False,
            "alpn": "h2",
            "ja3": "ja3_new",
            "ja4": "ja4_new",  # delta mid-session
            "bytes_out": 900,
            "bytes_in": 1000,
            "packet_count_out": 6,
            "packet_count_in": 6,
            "iat_ms": [12, 11, 9],
            "queried_subdomains": ["test"],
            "resolver_name": "evil-resolver.example",
            "cdn_sni": True,
        }
    )

    print(hunter.generate_report())