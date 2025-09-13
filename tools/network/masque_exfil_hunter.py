import base64
import datetime
import hashlib
import hmac
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


VERSION = "0.1.0"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class EthicalUse:
    @staticmethod
    def banner():
        msg = (
            "MASQUE/HTTP3 Covert Proxy Exfil Hunter v%s\n"
            "ETHICAL USE NOTICE: This tool is for authorized security testing, monitoring, "
            "and forensic investigations within your legal authority. Do not use on networks, "
            "hosts, or data you do not own or explicitly have permission to assess.\n"
        ) % VERSION
        return msg


class TimeAuthority:
    """
    Provides a trusted timestamp with attestation metadata.
    This offline-friendly implementation records the system time and a monotonic
    nonce. In production, integrate with Roughtime or RFC3161 TSA for attestations.
    """

    def __init__(self):
        self._nonce_counter = int(time.monotonic_ns())

    def get_attested_time(self) -> Dict[str, Any]:
        self._nonce_counter += 1
        now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
        ts_iso = now.isoformat()
        att = {
            "timestamp": ts_iso,
            "source": "system_clock",
            "nonce": self._nonce_counter,
            "evidence": None,
            "standards": ["Roughtime", "RFC3161"],
            "note": "For production, replace with real Roughtime/RFC3161 attestations.",
        }
        att["digest"] = sha256_hex(canonical_json(att))
        return att


class HSMStub:
    """
    Simulated HSM-protected key derivation for rotating salts.
    - Master key loaded from env var HSM_MASTER_KEY (base64url). If not provided, generated ephemeral.
    - Salt rotates every rotation_seconds using HMAC(master, epoch_index).
    """

    def __init__(self, rotation_seconds: int = 86400):
        self.rotation_seconds = rotation_seconds
        key_b64 = os.environ.get("HSM_MASTER_KEY")
        if key_b64:
            try:
                self.master_key = base64.urlsafe_b64decode(key_b64 + "===")
            except Exception:
                self.master_key = os.urandom(32)
        else:
            self.master_key = os.urandom(32)
        self._cached_epoch: Optional[int] = None
        self._cached_salt: Optional[bytes] = None

    def _current_epoch_index(self) -> int:
        return int(time.time() // self.rotation_seconds)

    def current_salt(self) -> Tuple[int, bytes]:
        epoch_index = self._current_epoch_index()
        if self._cached_epoch != epoch_index or self._cached_salt is None:
            msg = str(epoch_index).encode("ascii")
            salt = hmac.new(self.master_key, msg=msg, digestmod=hashlib.sha256).digest()
            self._cached_epoch = epoch_index
            self._cached_salt = salt
        return self._cached_epoch, self._cached_salt  # type: ignore

    def hash_identifier(self, value: str) -> Dict[str, Any]:
        epoch, salt = self.current_salt()
        mac = hmac.new(salt, msg=value.encode("utf-8"), digestmod=hashlib.sha256).digest()
        return {
            "hash": b64u(mac),
            "salt_epoch": epoch,
            "method": "HMAC-SHA256",
            "note": "Derived from rotating HSM-backed salt (simulated).",
        }


@dataclass
class DetectionRule:
    rule_id: str
    version: str
    name: str
    description: str
    signature: str
    sigstore_attested: bool
    rekor_log_id: Optional[str]
    params: Dict[str, Any] = field(default_factory=dict)

    def verify(self) -> bool:
        base = {
            "rule_id": self.rule_id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "params": self.params,
        }
        expected = sha256_hex(canonical_json(base) + b"|sigstore-attested")
        valid_sig = hmac.compare_digest(self.signature, expected)
        valid_attest = self.sigstore_attested and (self.rekor_log_id is None or len(self.rekor_log_id) > 0)
        return valid_sig and valid_attest


class RuleEngine:
    def __init__(self):
        self.rules: Dict[str, DetectionRule] = {}
        self._load_default_rules()

    def _sign_rule(self, base: Dict[str, Any]) -> str:
        # Simulated Sigstore signature: sha256(json||'sigstore-attested')
        return sha256_hex(canonical_json(base) + b"|sigstore-attested")

    def _load_default_rules(self):
        # Rule: Detect HTTP/3 CONNECT-UDP/CONNECT-IP indicating MASQUE tunnel
        base = {
            "rule_id": "R-MASQUE-CONNECT",
            "version": "1.0.0",
            "name": "HTTP/3 MASQUE CONNECT Tunnel",
            "description": "Detects HTTP/3 CONNECT-UDP or CONNECT-IP requests indicating a MASQUE tunnel.",
            "params": {"require_capsule_header": False, "min_datagrams": 1},
        }
        sig = self._sign_rule(base)
        rule = DetectionRule(
            rule_id=base["rule_id"],
            version=base["version"],
            name=base["name"],
            description=base["description"],
            params=base["params"],
            signature=sig,
            sigstore_attested=True,
            rekor_log_id="rekor:dummy-id",
        )
        self.rules[rule.rule_id] = rule

    def get_rules(self) -> List[DetectionRule]:
        return list(self.rules.values())

    def match(self, flow: Dict[str, Any]) -> List[Tuple[DetectionRule, Dict[str, Any]]]:
        matches: List[Tuple[DetectionRule, Dict[str, Any]]] = []
        for rule in self.get_rules():
            if not rule.verify():
                continue
            if rule.rule_id == "R-MASQUE-CONNECT":
                ind = self._match_masque_connect(flow, rule.params)
                if ind is not None:
                    matches.append((rule, ind))
        return matches

    def _match_masque_connect(self, flow: Dict[str, Any], params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Metadata expectations:
        # flow = {
        #   "protocol": "QUIC",
        #   "alpn": "h3",
        #   "http3": {"method": "CONNECT", "authority": "egress.example", "headers": {"capsule-protocol": "?1", ":protocol": "connect-udp"}},
        #   "quic": {"version": "0x1", "spin_bit": True, "datagrams": 10}, ...
        # }
        proto = str(flow.get("protocol", "")).upper()
        alpn = str(flow.get("alpn", "")).lower()
        http3 = flow.get("http3") or {}
        method = str(http3.get("method", "")).upper()
        headers = http3.get("headers") or {}
        protocol_hdr = str(headers.get(":protocol", "")).lower()
        # Alt detections
        path = str(http3.get("path", "")).lower()
        authority = str(http3.get("authority", "")).lower()
        quic = flow.get("quic") or {}
        datagrams = int(quic.get("datagrams") or 0)
        has_capsule = any(k.lower() == "capsule-protocol" for k in headers.keys())

        if not (proto == "QUIC" and alpn.startswith("h3")):
            return None

        is_connect_tunnel = method == "CONNECT" and protocol_hdr in ("connect-udp", "connect-ip")
        # Additional heuristics: well-known MASQUE paths or datagram usage
        well_known = path.startswith("/.well-known/masque/") or "masque" in path
        if not (is_connect_tunnel or (method == "CONNECT" and well_known)):
            return None

        if params.get("require_capsule_header", False) and not has_capsule:
            return None
        if datagrams < int(params.get("min_datagrams", 1)):
            # CONNECT-UDP uses QUIC DATAGRAM frames frequently
            return None

        indicators = {
            "masque_connect": True,
            "connect_protocol": protocol_hdr or ("masque" if well_known else None),
            "capsule_protocol_header": has_capsule,
            "datagrams": datagrams,
            "authority": authority,
            "path": path,
            "method": method,
        }
        return indicators


class EndpointFingerprintDB:
    """
    Stores integrity-verified endpoint fingerprints and allowlist.
    """

    def __init__(self):
        self._fingerprints: Dict[str, Dict[str, Any]] = {}
        self._allowlist: Dict[str, Dict[str, Any]] = {}
        self._load_from_env()

    def _load_from_env(self):
        # MASQUE_ALLOWLIST expects JSON array of objects: {"authority":"egress.example", "fingerprint":"ja4s-hash", "attested":true}
        raw = os.environ.get("MASQUE_ALLOWLIST")
        if not raw:
            return
        try:
            arr = json.loads(raw)
            for item in arr:
                auth = str(item.get("authority", "")).lower()
                if not auth:
                    continue
                self._allowlist[auth] = item
                if "fingerprint" in item:
                    self._fingerprints[auth] = {"fingerprint": item["fingerprint"], "attested": bool(item.get("attested", False))}
        except Exception:
            # silently ignore malformed env in this context
            pass

    def is_allowlisted(self, authority: str, ja4s: Optional[str]) -> bool:
        key = authority.lower()
        item = self._allowlist.get(key)
        if not item:
            return False
        # Verify attestation (simulated)
        if not bool(item.get("attested", False)):
            return False
        expected_fp = item.get("fingerprint")
        if expected_fp and ja4s:
            return hmac.compare_digest(expected_fp, ja4s)
        return True

    def verify_attestation(self, authority: str) -> bool:
        item = self._allowlist.get(authority.lower())
        return bool(item and item.get("attested", False))


def compute_ja4q(flow: Dict[str, Any]) -> str:
    # Simplified QUIC fingerprint:
    quic = flow.get("quic") or {}
    ver = str(quic.get("version", ""))
    alpn = str(flow.get("alpn", "")).lower()
    spin = "1" if quic.get("spin_bit") else "0"
    chlo_params = quic.get("client_params") or {}
    groups = chlo_params.get("groups") or []
    cs = chlo_params.get("ciphers") or []
    token = f"q/{ver[:6]}/{alpn}/s{spin}/g{len(groups):02d}/c{len(cs):02d}"
    return token


def compute_ja4s(flow: Dict[str, Any]) -> str:
    quic = flow.get("quic") or {}
    srv_params = quic.get("server_params") or {}
    ver = str(quic.get("version", ""))
    alpn = str(flow.get("alpn", "")).lower()
    cid_len = int(quic.get("server_cid_len") or 0)
    cert_ch = srv_params.get("cert_chain_len") or 0
    token = f"s/{ver[:6]}/{alpn}/cid{cid_len:02d}/cert{int(cert_ch):02d}"
    return token


class EvidenceSealer:
    def __init__(self, time_authority: TimeAuthority):
        self.ta = time_authority
        key_b64 = os.environ.get("EVIDENCE_SEAL_KEY")
        if key_b64:
            try:
                self.key = base64.urlsafe_b64decode(key_b64 + "===")
            except Exception:
                self.key = os.urandom(32)
        else:
            self.key = os.urandom(32)

    def seal(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        ts_att = self.ta.get_attested_time()
        envelope = {
            "schema": "masque-exfil-hunter.evidence/1.0",
            "timestamp_attestation": ts_att,
            "evidence": evidence,
        }
        digest = sha256_hex(canonical_json(envelope))
        signature = hmac.new(self.key, msg=canonical_json(envelope), digestmod=hashlib.sha256).digest()
        return {
            "envelope": envelope,
            "digest": digest,
            "hmac": b64u(signature),
            "alg": "HMAC-SHA256",
        }


@dataclass
class Alert:
    alert_id: str
    severity: str
    confidence: str
    classification: str
    summary: str
    indicators: Dict[str, Any]
    evidence_bundle: Dict[str, Any]
    rule: Dict[str, Any]
    audit_only: bool = False

    def to_json(self) -> str:
        return json.dumps(
            {
                "alert_id": self.alert_id,
                "severity": self.severity,
                "confidence": self.confidence,
                "classification": self.classification,
                "summary": self.summary,
                "indicators": self.indicators,
                "evidence_bundle": self.evidence_bundle,
                "rule": self.rule,
                "audit_only": self.audit_only,
                "version": VERSION,
            },
            ensure_ascii=False,
        )


class MASQUEHunter:
    def __init__(self):
        self.hsm = HSMStub()
        self.rules = RuleEngine()
        self.fpdb = EndpointFingerprintDB()
        self.ta = TimeAuthority()
        self.sealer = EvidenceSealer(self.ta)
        self.false_positive_rate_window: List[bool] = []  # Track decisions for rough FP rate if needed

    def analyze_flow(self, flow: Dict[str, Any]) -> List[Alert]:
        alerts: List[Alert] = []
        matches = self.rules.match(flow)
        # compute fingerprints and hashed identifiers
        ja4 = compute_ja4q(flow)
        ja4s = compute_ja4s(flow)
        http3 = flow.get("http3") or {}
        authority = str(http3.get("authority", "")).lower()
        # hashed identifiers for privacy
        cid_hash = self.hsm.hash_identifier(str(flow.get("client_ip", "")))
        sid_hash = self.hsm.hash_identifier(str(flow.get("server_ip", "")))
        sni_hash = self.hsm.hash_identifier(str(flow.get("sni", authority)))

        # build a minimal PCAP-like header (metadata only)
        ts = flow.get("timestamp") or time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        pcap_header = {
            "ts_sec": ts_sec,
            "ts_usec": ts_usec,
            "snaplen": int(flow.get("snaplen", 262144)),
            "linktype": int(flow.get("linktype", 1)),  # LINKTYPE_ETHERNET default
        }

        # baseline: if no matches and traffic is non-CONNECT QUIC web, do not flag
        if not matches:
            # track FP baseline event
            self.false_positive_rate_window.append(False)
            return alerts

        for rule, indicators in matches:
            # Determine allowlist status
            audit_only = False
            allowlisted = False
            if authority:
                allowlisted = self.fpdb.is_allowlisted(authority, ja4s)
            if allowlisted:
                audit_only = True

            # Severity/confidence
            severity = "high" if not audit_only else "info"
            confidence = "high"  # Clear semantics

            classification = "covert_tunnel" if not audit_only else "policy-allowed-tunnel"
            summary = (
                "HTTP/3 MASQUE CONNECT tunnel detected to %s (CONNECT-%s)."
                % (authority or "<unknown>", indicators.get("connect_protocol") or "masque")
            )
            if audit_only:
                summary = "Policy-allowed MASQUE tunnel observed to %s; alert suppressed (audited only)." % (authority or "<unknown>")

            flow_stats = {
                "packets": int(flow.get("packets", 0)),
                "bytes": int(flow.get("bytes", 0)),
                "duration_ms": int(flow.get("duration_ms", 0)),
                "rtt_ms": int((flow.get("quic") or {}).get("rtt_ms", 0)),
                "spin_bit_observed": bool((flow.get("quic") or {}).get("spin_bit", False)),
                "datagram_rate_per_s": float((flow.get("quic") or {}).get("datagram_rate", 0.0)),
            }

            evidence = {
                "pcap_header": pcap_header,
                "ja4_quic": ja4,
                "ja4s_quic": ja4s,
                "flow_stats": flow_stats,
                "hashed_identifiers": {
                    "client_ip": cid_hash,
                    "server_ip": sid_hash,
                    "sni_or_authority": sni_hash,
                },
                "indicators": indicators,
                "protocol": flow.get("protocol"),
                "alpn": flow.get("alpn"),
            }

            sealed = self.sealer.seal(evidence)

            alert = Alert(
                alert_id=b64u(os.urandom(12)),
                severity=severity,
                confidence=confidence,
                classification=classification,
                summary=summary,
                indicators=indicators,
                evidence_bundle=sealed,
                rule={
                    "rule_id": rule.rule_id,
                    "version": rule.version,
                    "signature_valid": rule.verify(),
                },
                audit_only=audit_only,
            )
            alerts.append(alert)
            # Update FP window: consider audit-only not a false positive
            self.false_positive_rate_window.append(False)
        return alerts


def parse_args(argv: List[str]) -> Dict[str, Any]:
    # Minimal arg parsing for a simple CLI
    args = {
        "mode": "analyze",
        "input": None,
        "quiet": False,
    }
    it = iter(argv[1:])
    for a in it:
        if a in ("-h", "--help"):
            args["mode"] = "help"
        elif a in ("-q", "--quiet"):
            args["quiet"] = True
        elif a in ("-i", "--input"):
            try:
                args["input"] = next(it)
            except StopIteration:
                print("Error: --input requires a path", file=sys.stderr)
                sys.exit(2)
        elif a == "version":
            args["mode"] = "version"
        elif a == "analyze":
            args["mode"] = "analyze"
        else:
            # unknown positional: assume input file
            args["input"] = a
    return args


def main():
    args = parse_args(sys.argv)
    if args["mode"] == "help":
        print(EthicalUse.banner())
        print("Usage: python -m tools.network.masque_exfil_hunter [analyze] [-i file.jsonl] [--quiet] | version")
        print("Input format: JSON lines with QUIC/HTTP3 flow metadata (no payloads).")
        return
    if args["mode"] == "version":
        print(VERSION)
        return

    if not args["quiet"]:
        print(EthicalUse.banner().rstrip())

    hunter = MASQUEHunter()

    # Input: JSON lines from stdin or file
    f = sys.stdin
    if args["input"]:
        try:
            f = open(args["input"], "r", encoding="utf-8")
        except Exception as e:
            print(f"Error opening input: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                flow = json.loads(line)
            except Exception as e:
                print(json.dumps({"error": "Invalid JSON line", "detail": str(e)}))
                continue
            alerts = hunter.analyze_flow(flow)
            if not alerts:
                continue
            for alert in alerts:
                print(alert.to_json())
    except KeyboardInterrupt:
        pass
    finally:
        if f is not sys.stdin:
            try:
                f.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()