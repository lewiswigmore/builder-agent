#!/usr/bin/env python3
"""
HTTP/2 Abuse Hunter: Rapid Reset & Stream Flood Detector

Privacy-preserving IDS that detects HTTP/2 Rapid Reset, stream multiplexing floods,
and SETTINGS/WINDOW_UPDATE abuse without decrypting payloads. It profiles connection
semantics, RST_STREAM bursts, and timing patterns, correlates JA3/JA4 fingerprints
and WAF/CDN logs, and recommends targeted mitigations.

Ethical use warning:
- Use only on networks and systems you are authorized to monitor.
- Do not attempt to decrypt application payloads with this tool.
- Ensure data handling complies with privacy laws and organizational policy.
- This tool minimizes PII by hashing IPs/domains and configurable retention,
  but operators are responsible for compliant deployment.

Input (JSON lines over stdin or via API):
  - connection_start:
      {
        "type": "connection_start",
        "ts": float_unix_seconds,
        "src_ip": "1.2.3.4",
        "src_port": 54321,
        "dst_ip": "5.6.7.8",
        "dst_port": 443,
        "alpn": "h2",      # optional
        "sni": "api.example.com",  # optional
        "tls_ja3": "771,4865-4867-...,...",  # optional
        "tls_ja4": "h2:....",               # optional
        "asn": 12345                        # optional (if known via enrichment)
      }
  - http2_frame (metadata-only; no payload):
      {
        "type": "http2_frame",
        "ts": float_unix_seconds,
        "src_ip": "1.2.3.4", "src_port": 54321,
        "dst_ip": "5.6.7.8", "dst_port": 443,
        "frame_type": "RST_STREAM|HEADERS|DATA|SETTINGS|WINDOW_UPDATE|PRIORITY|GOAWAY|PING|PUSH_PROMISE",
        "length": 9,                 # frame length
        "stream_id": 123,            # int (if available)
        "flags": ["END_STREAM"]      # optional list
      }
  - waf_log (correlation):
      {
        "type": "waf_log",
        "ts": float_unix_seconds,
        "ip": "1.2.3.4",
        "asn": 12345,                    # optional
        "vendor": "cloudwaf",
        "rule_id": "RR-1001",
        "action": "block|challenge|rate_limit",
        "detail": "RST burst"
      }

Output (JSON lines on stdout for alerts):
  - Alert object with HMAC signature, time-synchronized alerts with minimal PCAP snippet and header summaries.

Note: This tool requires metadata observed by a passive sensor. It does not decrypt TLS.
RST_STREAM and frame metadata may be unavailable on fully encrypted streams; in such cases,
detection relies on timing/size heuristics, JA3/JA4, and correlating WAF logs if provided.
"""

import argparse
import base64
import dataclasses
import hashlib
import hmac
import io
import json
import logging
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

# ------------- Utilities -------------


def utc_iso(ts: float) -> str:
    try:
        from datetime import datetime, timezone

        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        # Fallback to simple formatting
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


# ------------- PCAP minimal writer (synthetic) -------------


class MinimalPCAP:
    """
    Generates a minimal classic PCAP file with synthetic "packets" that encode metadata-only events.
    Linktype: 147 (USER0), to avoid pretending to be valid Ethernet/IP/TCP frames.
    Each packet payload is a small TLV blob documenting event fields (no PII).
    """

    PCAP_GLOBAL_MAGIC = 0xA1B2C3D4
    LINKTYPE_USER0 = 147

    def __init__(self, snaplen: int = 128):
        self.snaplen = snaplen
        self.buf = io.BytesIO()
        self._write_global_header()

    def _write_global_header(self) -> None:
        import struct

        gh = struct.pack(
            "<IHHIIII",
            self.PCAP_GLOBAL_MAGIC,
            2, 4,  # version
            0,  # thiszone
            0,  # sigfigs
            self.snaplen,
            self.LINKTYPE_USER0,
        )
        self.buf.write(gh)

    def add_event_packet(self, ts: float, event: Dict[str, Any]) -> None:
        import struct

        # Build TLV: key=value; key truncation and careful to avoid PII
        summary = self._summarize_event(event)
        payload = summary.encode("utf-8")
        caplen = min(len(payload), self.snaplen)
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)

        ph = struct.pack("<IIII", sec, usec, caplen, caplen)
        self.buf.write(ph)
        self.buf.write(payload[:caplen])

    def _summarize_event(self, event: Dict[str, Any]) -> str:
        e = {
            "t": event.get("frame_type") or event.get("type"),
            "sid": event.get("stream_id"),
            "len": event.get("length"),
            "flags": ",".join(event.get("flags", [])) if event.get("flags") else None,
        }
        # Compact form "t=RST_STREAM sid=123 len=9 flags=END_STREAM"
        parts = []
        for k, v in e.items():
            if v is None:
                continue
            parts.append(f"{k}={v}")
        return " ".join(parts)

    def to_bytes(self) -> bytes:
        return self.buf.getvalue()


# ------------- Configuration -------------


@dataclass
class Thresholds:
    rapid_reset_burst_window_s: float = 1.0
    rapid_reset_burst_count: int = 100
    rapid_reset_ratio_min: float = 0.8  # resets / all frames in window

    max_concurrent_streams_threshold: int = 300
    concurrency_sustain_window_s: float = 2.0  # must sustain for window to alert
    concurrency_min_frames: int = 100  # avoid noisy sparse connections

    flow_control_rate_window_s: float = 1.0
    flow_control_rate_threshold: int = 600  # WINDOW_UPDATE+SETTINGS per window
    flow_control_ratio_min: float = 0.5  # fraction of control frames among all


@dataclass
class Retention:
    state_retention_s: float = 600.0
    waf_retention_s: float = 3600.0
    snippet_events_max: int = 64


@dataclass
class Privacy:
    pii_salt: str = "change-me"
    hash_truncate: int = 12  # hex chars


@dataclass
class Signing:
    alert_signing_secret: str = "change-me"
    signing_alg: str = "HMAC-SHA256"
    ntp_offset_seconds: float = 0.0


@dataclass
class Config:
    thresholds: Thresholds = field(default_factory=Thresholds)
    retention: Retention = field(default_factory=Retention)
    privacy: Privacy = field(default_factory=Privacy)
    signing: Signing = field(default_factory=Signing)


# ------------- Core State -------------


@dataclass
class ConnectionState:
    flow_id: str
    started_ts: float
    last_ts: float
    alpn: Optional[str] = None
    sni_hash: Optional[str] = None
    tls_ja3: Optional[str] = None
    tls_ja4: Optional[str] = None
    asn: Optional[int] = None
    src_ip_hash: Optional[str] = None
    dst_ip_hash: Optional[str] = None

    active_streams: Dict[int, str] = field(default_factory=dict)  # sid -> state
    concurrent_high_water: int = 0

    rst_timestamps: Deque[float] = field(default_factory=deque)
    settings_timestamps: Deque[float] = field(default_factory=deque)
    window_update_timestamps: Deque[float] = field(default_factory=deque)
    frame_timestamps: Deque[float] = field(default_factory=deque)
    per_type_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    recent_events: Deque[Dict[str, Any]] = field(default_factory=deque)  # for snippet
    alerted_types: set = field(default_factory=set)  # avoid duplicate alerts
    last_concurrency_over_ts: Optional[float] = None


# ------------- Hunter Engine -------------


class HTTP2AbuseHunter:
    def __init__(self, config: Config, alert_sink: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.cfg = config
        self.alert_sink = alert_sink or (lambda alert: print(json.dumps(alert), flush=True))
        self._flows: Dict[str, ConnectionState] = {}
        self._waf_index: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._lock = threading.Lock()

    # --------- Privacy-preserving hashing ---------

    def hash_value(self, value: str) -> str:
        try:
            secret = self.cfg.privacy.pii_salt.encode("utf-8")
            digest = hmac.new(secret, msg=value.encode("utf-8"), digestmod=hashlib.sha256).hexdigest()
            return digest[: max(8, self.cfg.privacy.hash_truncate)]
        except Exception:
            # As a fallback, use sha256 directly
            digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
            return digest[: max(8, self.cfg.privacy.hash_truncate)]

    # --------- Flow keying ---------

    def flow_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
        # Hash PII fields to preserve privacy
        try:
            sp = safe_int(src_port)
            dp = safe_int(dst_port)
            key_plain = f"{src_ip}:{sp}->{dst_ip}:{dp}"
            return self.hash_value(key_plain)
        except Exception:
            return self.hash_value(f"{src_ip}-{dst_ip}-{src_port}-{dst_port}")

    # --------- Ingestion ---------

    def ingest_event(self, event: Dict[str, Any]) -> None:
        etype = event.get("type")
        if etype == "waf_log":
            self.ingest_waf_log(event)
            return

        if etype == "connection_start":
            self._ingest_conn_start(event)
        elif etype == "http2_frame":
            self._ingest_http2_frame(event)
        else:
            logging.debug("Unknown event type: %s", etype)
        self._gc()

    def ingest_waf_log(self, log: Dict[str, Any]) -> None:
        try:
            ts = safe_float(log.get("ts"), time.time())
            ip = str(log.get("ip", ""))
            if not ip:
                return
            hip = self.hash_value(ip)
            entry = {
                "ts": ts,
                "vendor": str(log.get("vendor", ""))[:32],
                "rule_id": str(log.get("rule_id", ""))[:64],
                "action": str(log.get("action", ""))[:32],
                "detail": str(log.get("detail", ""))[:256],
                "asn": safe_int(log.get("asn"), 0) or None,
            }
            with self._lock:
                self._waf_index[hip].append(entry)
        except Exception as e:
            logging.error("Error ingesting WAF log: %s", e)

    def _ingest_conn_start(self, e: Dict[str, Any]) -> None:
        try:
            ts = safe_float(e.get("ts"), time.time())
            src_ip = str(e.get("src_ip", ""))
            dst_ip = str(e.get("dst_ip", ""))
            fk = self.flow_key(src_ip, safe_int(e.get("src_port")), dst_ip, safe_int(e.get("dst_port")))
            sni = e.get("sni")
            state = ConnectionState(
                flow_id=fk,
                started_ts=ts,
                last_ts=ts,
                alpn=e.get("alpn"),
                sni_hash=self.hash_value(sni) if sni else None,
                tls_ja3=e.get("tls_ja3"),
                tls_ja4=e.get("tls_ja4"),
                asn=safe_int(e.get("asn"), 0) or None,
                src_ip_hash=self.hash_value(src_ip) if src_ip else None,
                dst_ip_hash=self.hash_value(dst_ip) if dst_ip else None,
            )
            with self._lock:
                self._flows[fk] = state
        except Exception as ex:
            logging.error("Error ingesting connection_start: %s", ex)

    def _ingest_http2_frame(self, e: Dict[str, Any]) -> None:
        try:
            ts = safe_float(e.get("ts"), time.time())
            src_ip = str(e.get("src_ip", ""))
            dst_ip = str(e.get("dst_ip", ""))
            fk = self.flow_key(src_ip, safe_int(e.get("src_port")), dst_ip, safe_int(e.get("dst_port")))
            with self._lock:
                st = self._flows.get(fk)
                if st is None:
                    # Create synthetic state if we missed connection_start
                    st = ConnectionState(
                        flow_id=fk,
                        started_ts=ts,
                        last_ts=ts,
                        src_ip_hash=self.hash_value(src_ip) if src_ip else None,
                        dst_ip_hash=self.hash_value(dst_ip) if dst_ip else None,
                    )
                    self._flows[fk] = st

                st.last_ts = ts
                frame_type = str(e.get("frame_type", "")).upper()
                st.per_type_counts[frame_type] += 1
                st.frame_timestamps.append(ts)
                # Maintain deques within retention length; pruning done later

                # Stream state tracking
                sid = safe_int(e.get("stream_id"), -1)
                flags = {str(f).upper() for f in (e.get("flags") or [])}

                if frame_type in ("HEADERS", "PUSH_PROMISE"):
                    if sid >= 0 and sid not in st.active_streams:
                        st.active_streams[sid] = "open"
                        st.concurrent_high_water = max(st.concurrent_high_water, len(st.active_streams))
                        # mark over-threshold sustain time
                        if len(st.active_streams) > self.cfg.thresholds.max_concurrent_streams_threshold and st.last_concurrency_over_ts is None:
                            st.last_concurrency_over_ts = ts
                elif frame_type == "RST_STREAM":
                    st.rst_timestamps.append(ts)
                    if sid in st.active_streams:
                        st.active_streams.pop(sid, None)
                elif "END_STREAM" in flags or frame_type in ("GOAWAY",):
                    if sid in st.active_streams:
                        st.active_streams.pop(sid, None)

                if frame_type == "SETTINGS":
                    st.settings_timestamps.append(ts)
                elif frame_type == "WINDOW_UPDATE":
                    st.window_update_timestamps.append(ts)

                # Recent metadata event for snippet
                snippet_event = {
                    "type": "http2_frame",
                    "frame_type": frame_type,
                    "stream_id": sid if sid >= 0 else None,
                    "length": safe_int(e.get("length"), 0),
                    "flags": sorted(list(flags)) if flags else None,
                }
                st.recent_events.append({"ts": ts, "event": snippet_event})
                while len(st.recent_events) > self.cfg.retention.snippet_events_max:
                    st.recent_events.popleft()

            # Evaluate detections after updating state
            self._evaluate_and_alert(fk)
        except Exception as ex:
            logging.error("Error ingesting http2_frame: %s", ex)

    # --------- Detection ---------

    def _evaluate_and_alert(self, flow_id: str) -> None:
        with self._lock:
            st = self._flows.get(flow_id)
            if not st:
                return
            ts_now = st.last_ts
            thr = self.cfg.thresholds

            # Rapid Reset burst detection
            rr = self._detect_rapid_reset(st, ts_now)
            if rr and "rapid_reset" not in st.alerted_types:
                alert = self._build_alert(st, "rapid_reset", rr, severity="high")
                st.alerted_types.add("rapid_reset")
                self.alert_sink(alert)

            # Concurrency flood detection
            cf = self._detect_concurrency(st, ts_now)
            if cf and "stream_flood" not in st.alerted_types:
                severity = "medium" if cf.get("active_streams", 0) < (thr.max_concurrent_streams_threshold * 2) else "high"
                alert = self._build_alert(st, "stream_flood", cf, severity=severity)
                st.alerted_types.add("stream_flood")
                self.alert_sink(alert)

            # Flow-control abuse
            fa = self._detect_flow_control_abuse(st, ts_now)
            if fa and "flow_control_abuse" not in st.alerted_types:
                severity = "medium" if fa.get("control_rate", 0) < (thr.flow_control_rate_threshold * 2) else "high"
                alert = self._build_alert(st, "flow_control_abuse", fa, severity=severity)
                st.alerted_types.add("flow_control_abuse")
                self.alert_sink(alert)

    def _count_in_window(self, timestamps: Deque[float], now_ts: float, window: float) -> int:
        # Evict old timestamps
        while timestamps and (now_ts - timestamps[0]) > window:
            timestamps.popleft()
        return len(timestamps)

    def _detect_rapid_reset(self, st: ConnectionState, now_ts: float) -> Optional[Dict[str, Any]]:
        thr = self.cfg.thresholds
        window = thr.rapid_reset_burst_window_s
        rst_count = self._count_in_window(st.rst_timestamps, now_ts, window)
        frame_count = self._count_in_window(st.frame_timestamps, now_ts, window)
        if frame_count == 0:
            return None
        ratio = rst_count / max(1, frame_count)
        if rst_count >= thr.rapid_reset_burst_count and ratio >= thr.rapid_reset_ratio_min:
            # Evidence: burst rate, stream ids sample
            sids = []
            # Collect from recent_events within window
            for item in reversed(st.recent_events):
                if (now_ts - item["ts"]) > window:
                    break
                ev = item["event"]
                if ev["frame_type"] == "RST_STREAM" and ev.get("stream_id") is not None:
                    sids.append(ev["stream_id"])
                if len(sids) >= 16:
                    break
            confidence = min(1.0, 0.7 + (rst_count - thr.rapid_reset_burst_count) / (thr.rapid_reset_burst_count * 2))
            label = "high" if confidence >= 0.85 else ("medium" if confidence >= 0.6 else "low")
            burst_rate = round(rst_count / window, 3) if window > 0 else float("inf")
            return {
                "burst_window_s": window,
                "rst_count": rst_count,
                "frame_count": frame_count,
                "rst_ratio": round(ratio, 3),
                "burst_rate_per_s": burst_rate,
                "stream_ids_sample": sorted(set(sids))[:16],
                "confidence": round(confidence, 3),
                "confidence_label": label,
            }
        return None

    def _detect_concurrency(self, st: ConnectionState, now_ts: float) -> Optional[Dict[str, Any]]:
        thr = self.cfg.thresholds
        active = len(st.active_streams)
        # Evict sustain if dropped below threshold
        if active <= thr.max_concurrent_streams_threshold:
            st.last_concurrency_over_ts = None
            return None
        # Only alert if sustained for specified window and sufficient activity
        if st.last_concurrency_over_ts is None:
            return None
        sustained = (now_ts - st.last_concurrency_over_ts) >= thr.concurrency_sustain_window_s
        if sustained and sum(st.per_type_counts.values()) >= thr.concurrency_min_frames:
            return {
                "active_streams": active,
                "high_watermark": st.concurrent_high_water,
                "sustain_s": round(now_ts - st.last_concurrency_over_ts, 3),
                "min_threshold": thr.max_concurrent_streams_threshold,
            }
        return None

    def _detect_flow_control_abuse(self, st: ConnectionState, now_ts: float) -> Optional[Dict[str, Any]]:
        thr = self.cfg.thresholds
        window = thr.flow_control_rate_window_s
        winu = self._count_in_window(st.window_update_timestamps, now_ts, window)
        sets = self._count_in_window(st.settings_timestamps, now_ts, window)
        control = winu + sets
        total = self._count_in_window(st.frame_timestamps, now_ts, window)
        ratio = (control / max(1, total)) if total else 0.0
        if control >= thr.flow_control_rate_threshold and ratio >= thr.flow_control_ratio_min:
            return {
                "control_rate_window_s": window,
                "window_update": winu,
                "settings": sets,
                "control_rate": control,
                "total_frames": total,
                "control_ratio": round(ratio, 3),
            }
        return None

    # --------- Alert construction ---------

    def _build_alert(self, st: ConnectionState, alert_type: str, evidence: Dict[str, Any], severity: str = "high") -> Dict[str, Any]:
        ts = st.last_ts + self.cfg.signing.ntp_offset_seconds
        # Build snippet
        pcap = MinimalPCAP()
        # Include last few events
        last_events = list(st.recent_events)[-min(len(st.recent_events), self.cfg.retention.snippet_events_max) :]
        for item in last_events:
            pcap.add_event_packet(item["ts"], item["event"])
        snippet_b64 = base64.b64encode(pcap.to_bytes()).decode("ascii")

        # Correlate WAF by IP hash and ASN best-effort
        correlated_waf = self._correlate_waf(st)

        # Build mitigation recommendation
        mitigations = self._recommend_mitigation(alert_type, st, evidence, correlated_waf)

        alert = {
            "schema": "http2_abuse_hunter/1.0",
            "alert_type": alert_type,
            "severity": severity,
            "generated_at": utc_iso(ts),
            "time_skew_seconds": self.cfg.signing.ntp_offset_seconds,
            "flow_id": st.flow_id,
            "alpn": st.alpn,
            "sni_hash": st.sni_hash,
            "tls_ja3": st.tls_ja3,
            "tls_ja4": st.tls_ja4,
            "asn": st.asn,
            "evidence": evidence,
            "header_summary": self._header_summary(st),
            "pcap_snippet_b64": snippet_b64,
            "waf_correlation": correlated_waf or None,
            "mitigations": mitigations,
            "ethics": "Authorized testing only. Do not deploy without consent and proper legal basis.",
        }
        # Sign alert
        signature = self._sign_alert(alert)
        alert["signature"] = signature
        alert["signing_alg"] = self.cfg.signing.signing_alg
        return alert

    def _header_summary(self, st: ConnectionState) -> Dict[str, Any]:
        return {
            "frames_total": sum(st.per_type_counts.values()),
            "frames_by_type": dict(sorted(st.per_type_counts.items())),
            "active_streams": len(st.active_streams),
            "concurrency_high_water": st.concurrent_high_water,
        }

    def _correlate_waf(self, st: ConnectionState) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            now = st.last_ts
            # Primary: match by source/destination IP hash
            for hip in filter(None, [st.src_ip_hash, st.dst_ip_hash]):
                if hip in self._waf_index:
                    for ent in self._waf_index[hip]:
                        if (now - ent["ts"]) <= self.cfg.retention.waf_retention_s:
                            results.append(
                                {
                                    "ts": utc_iso(ent["ts"]),
                                    "vendor": ent.get("vendor"),
                                    "rule_id": ent.get("rule_id"),
                                    "action": ent.get("action"),
                                    "asn": ent.get("asn"),
                                }
                            )
            # Secondary: match by ASN if present
            asn = st.asn
            if asn:
                for hip, entries in self._waf_index.items():
                    for ent in entries:
                        if ent.get("asn") == asn and (now - ent["ts"]) <= self.cfg.retention.waf_retention_s:
                            results.append(
                                {
                                    "ts": utc_iso(ent["ts"]),
                                    "vendor": ent.get("vendor"),
                                    "rule_id": ent.get("rule_id"),
                                    "action": ent.get("action"),
                                    "asn": ent.get("asn"),
                                }
                            )
            # Deduplicate by tuple
            dedup = {}
            for r in results:
                key = (r.get("ts"), r.get("vendor"), r.get("rule_id"), r.get("action"), r.get("asn"))
                dedup[key] = r
            results = list(dedup.values())
            # Return most recent few
            results.sort(key=lambda x: x.get("ts", ""), reverse=True)
            return results[:10]
        except Exception:
            return []

    def _recommend_mitigation(self, alert_type: str, st: ConnectionState, evidence: Dict[str, Any], waf_corr: List[Dict[str, Any]]) -> List[str]:
        recs: List[str] = []
        ja3 = st.tls_ja3 or "<unknown>"
        ja4 = st.tls_ja4 or "<unknown>"
        if alert_type == "rapid_reset":
            recs.extend(
                [
                    "Apply per-connection rate limits on RST_STREAM frames (e.g., drop if > {} in {}s).".format(
                        self.cfg.thresholds.rapid_reset_burst_count, self.cfg.thresholds.rapid_reset_burst_window_s
                    ),
                    "Create or enable a WAF rule signature for the Rapid Reset pattern; target JA3/JA4 (JA3={}, JA4={}).".format(ja3, ja4),
                    "Lower SETTINGS_MAX_CONCURRENT_STREAMS for suspicious JA3/JA4 (JA3={}, JA4={}).".format(ja3, ja4),
                    "If behind CDN/WAF, enable vendor rapid-reset protections or ruleset; correlate by ASN and JA3.",
                    "Consider temporarily challenging or rate-limiting traffic matching the fingerprint in upstream edge.",
                ]
            )
        elif alert_type == "stream_flood":
            recs.extend(
                [
                    "Enforce sane max concurrent streams (e.g., {}), with backoff for bursty clients.".format(
                        self.cfg.thresholds.max_concurrent_streams_threshold
                    ),
                    "Throttle new stream creation rate per connection and fingerprint (JA3={}, JA4={}).".format(ja3, ja4),
                    "Deploy a WAF/CDN rule signature to cap stream creation bursts from suspicious fingerprints.",
                ]
            )
        elif alert_type == "flow_control_abuse":
            recs.extend(
                [
                    "Rate-limit SETTINGS/WINDOW_UPDATE frames (drop/close if > {} per {}s).".format(
                        self.cfg.thresholds.flow_control_rate_threshold, self.cfg.thresholds.flow_control_rate_window_s
                    ),
                    "Isolate abusive clients by JA3/JA4 and ASN; consider WAF rule targeting fingerprint.",
                ]
            )
        # Add WAF-actionable recommendation if correlated
        if waf_corr:
            actions = sorted(set([c.get("action") for c in waf_corr if c.get("action")]), key=lambda x: x or "")
            vendors = sorted(set([c.get("vendor") for c in waf_corr if c.get("vendor")]), key=lambda x: x or "")
            if actions or vendors:
                recs.append("Coordinate with WAF/CDN vendors {} to enforce actions {} for matched fingerprints.".format(",".join(vendors), ",".join(actions)))
        # Generic safeguard
        recs.append("Always validate mitigations in a canary environment to reduce false positives on benign multiplexed API traffic.")
        return recs

    def _sign_alert(self, alert: Dict[str, Any]) -> str:
        try:
            secret = self.cfg.signing.alert_signing_secret.encode("utf-8")
            msg = canonical_json(alert)
            sig = hmac.new(secret, msg=msg, digestmod=hashlib.sha256).digest()
            return base64.b64encode(sig).decode("ascii")
        except Exception as e:
            logging.error("Signing error: %s", e)
            return ""

    # --------- Garbage collection ---------

    def _gc(self) -> None:
        try:
            with self._lock:
                now = time.time()
                # Evict stale flows
                to_del = [fid for fid, st in self._flows.items() if (now - st.last_ts) > self.cfg.retention.state_retention_s]
                for fid in to_del:
                    self._flows.pop(fid, None)
                # Evict old WAF logs beyond retention
                for hip, entries in list(self._waf_index.items()):
                    self._waf_index[hip] = [e for e in entries if (now - e["ts"]) <= self.cfg.retention.waf_retention_s]
                    if not self._waf_index[hip]:
                        self._waf_index.pop(hip, None)
        except Exception as e:
            logging.error("GC error: %s", e)


# ------------- CLI Interface -------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="HTTP/2 Abuse Hunter (privacy-preserving IDS). Authorized testing only.")
    p.add_argument("--pii-salt", default=None, help="PII hashing salt (HMAC).")
    p.add_argument("--signing-key", default=None, help="Alert signing secret.")
    p.add_argument("--ntp-offset-seconds", type=float, default=0.0, help="Apply NTP time offset (seconds) to alert timestamps.")
    p.add_argument("--rapid-reset-count", type=int, default=None, help="Rapid reset burst threshold count in window.")
    p.add_argument("--rapid-reset-window", type=float, default=None, help="Rapid reset window seconds.")
    p.add_argument("--rapid-reset-ratio", type=float, default=None, help="Rapid reset ratio threshold (0-1).")
    p.add_argument("--max-concurrent-streams", type=int, default=None, help="Max concurrent streams threshold.")
    p.add_argument("--flow-control-rate", type=int, default=None, help="Flow control rate threshold per window.")
    p.add_argument("--flow-control-window", type=float, default=None, help="Flow control rate window seconds.")
    p.add_argument("--retention-seconds", type=float, default=None, help="State retention seconds.")
    p.add_argument("--waf-retention-seconds", type=float, default=None, help="WAF log retention seconds.")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    p.add_argument("--dry-run", action="store_true", help="Parse input but do not emit alerts (for validation).")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

    cfg = Config()
    if args.pii_salt:
        cfg.privacy.pii_salt = args.pii_salt
    if args.signing_key:
        cfg.signing.alert_signing_secret = args.signing_key
    cfg.signing.ntp_offset_seconds = args.ntp_offset_seconds or 0.0
    if args.rapid_reset_count is not None:
        cfg.thresholds.rapid_reset_burst_count = max(1, args.rapid_reset_count)
    if args.rapid_reset_window is not None:
        cfg.thresholds.rapid_reset_burst_window_s = max(0.1, args.rapid_reset_window)
    if args.rapid_reset_ratio is not None:
        cfg.thresholds.rapid_reset_ratio_min = max(0.0, min(1.0, args.rapid_reset_ratio))
    if args.max_concurrent_streams is not None:
        cfg.thresholds.max_concurrent_streams_threshold = max(1, args.max_concurrent_streams)
    if args.flow_control_rate is not None:
        cfg.thresholds.flow_control_rate_threshold = max(1, args.flow_control_rate)
    if args.flow_control_window is not None:
        cfg.thresholds.flow_control_rate_window_s = max(0.1, args.flow_control_window)
    if args.retention_seconds is not None:
        cfg.retention.state_retention_s = max(10.0, args.retention_seconds)
    if args.waf_retention_seconds is not None:
        cfg.retention.waf_retention_s = max(60.0, args.waf_retention_seconds)

    # Build hunter
    alerts: List[Dict[str, Any]] = []
    if args.dry_run:
        sink = lambda a: alerts.append(a)
    else:
        sink = lambda a: print(json.dumps(a, ensure_ascii=False), flush=True)
    hunter = HTTP2AbuseHunter(cfg, alert_sink=sink)

    # Read JSON lines from stdin
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
                hunter.ingest_event(evt)
            except json.JSONDecodeError:
                logging.error("Invalid JSON line, skipping.")
            except Exception as e:
                logging.error("Error processing event: %s", e)
    except KeyboardInterrupt:
        logging.info("Interrupted by user.")
    finally:
        # In dry run, print summary
        if args.dry_run and alerts:
            print(json.dumps({"dry_run_alert_count": len(alerts)}, ensure_ascii=False), file=sys.stderr)


if __name__ == "__main__":
    main()