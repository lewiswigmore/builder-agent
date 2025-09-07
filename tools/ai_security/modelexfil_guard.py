import base64
import collections
import datetime
import hashlib
import hmac
import json
import math
import os
import random
import re
import secrets
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Tuple

# Ethical warning: This tool is intended for authorized defensive security testing and production protection only.
# Do not use to profile or deanonymize users. The guard stores only privacy-preserving, feature-level telemetry.


def _utcnow_iso() -> str:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()


class PiiRedactor:
    EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
    PHONE = re.compile(r"\b(?:\+?\d{1,3})?[-.\s(]*\d{3}[-.\s)]*\d{3}[-.\s]*\d{4}\b")
    SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    URL = re.compile(r"\bhttps?://[^\s]+")
    IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    CREDIT = re.compile(r"\b(?:\d[ -]*?){13,16}\b")

    @classmethod
    def redact(cls, text: str) -> str:
        if not text:
            return ""
        t = text
        t = cls.EMAIL.sub("[REDACTED_EMAIL]", t)
        t = cls.PHONE.sub("[REDACTED_PHONE]", t)
        t = cls.SSN.sub("[REDACTED_SSN]", t)
        t = cls.URL.sub("[REDACTED_URL]", t)
        t = cls.IP.sub("[REDACTED_IP]", t)
        t = cls.CREDIT.sub("[REDACTED_CARD]", t)
        return t


def _tokenize(text: str) -> List[str]:
    # Simple tokenization, lowercased words and special tokens
    return re.findall(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]", text.lower())


def _hash_str(s: str, nbytes: int = 8) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[: nbytes * 2]


def _laplace_noise(scale: float) -> float:
    u = random.random() - 0.5
    return -scale * math.copysign(1.0, u) * math.log(1 - 2 * abs(u) + 1e-12)


def _shannon_entropy(tokens: List[str]) -> float:
    if not tokens:
        return 0.0
    cnt = collections.Counter(tokens)
    total = sum(cnt.values())
    ent = 0.0
    for c in cnt.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def _simhash(tokens: List[str], bits: int = 64) -> int:
    if not tokens:
        return 0
    v = [0] * bits
    for tok in tokens:
        h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
        for i in range(bits):
            bit = 1 if (h >> i) & 1 else -1
            v[i] += bit
    out = 0
    for i in range(bits):
        if v[i] > 0:
            out |= (1 << i)
    return out


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def _bin_perplexity(char_dist: Dict[str, float], text: str) -> str:
    # Reference distribution (rough English letters + space + punctuation)
    ref = {
        "e": 0.127, "t": 0.091, "a": 0.082, "o": 0.075, "i": 0.070, "n": 0.067,
        " ": 0.18, "s": 0.063, "h": 0.061, "r": 0.060, "d": 0.043, "l": 0.040,
        "u": 0.028, "m": 0.024, "w": 0.024, "c": 0.028, "f": 0.022, "g": 0.020,
        "y": 0.020, "p": 0.019, "b": 0.015, "v": 0.010, "k": 0.008, "x": 0.002,
        "j": 0.002, "q": 0.001, "z": 0.001, ".": 0.01, ",": 0.01, "'": 0.005,
    }
    if not text:
        return "unknown"
    # Empirical char distribution
    t = text.lower()
    total = max(1, len(t))
    q = collections.Counter(t)
    # Only consider chars in ref to reduce leakage
    q_ref = {ch: q.get(ch, 0) / total for ch in ref.keys()}
    # Cross entropy H(p, q) ~ -sum p * log2(q + eps)
    eps = 1e-6
    cross_ent = -sum(ref[ch] * math.log2(q_ref.get(ch, 0) + eps) for ch in ref.keys())
    perplexity = 2 ** cross_ent
    # Bin into coarse buckets
    if perplexity < 3:
        return "low"
    elif perplexity < 6:
        return "medium"
    else:
        return "high"


class DifferentialPrivacy:
    def __init__(self, epsilon: float = 1.0):
        self.epsilon = max(1e-6, float(epsilon))

    def add_noise(self, value: float, sensitivity: float = 1.0) -> float:
        scale = sensitivity / self.epsilon
        return value + _laplace_noise(scale)


class FeatureExtractor:
    def __init__(self, dp: DifferentialPrivacy, ngram_n: int = 2, max_ngrams: int = 50):
        self.dp = dp
        self.ngram_n = ngram_n
        self.max_ngrams = max_ngrams

    def extract(self, text: str) -> Dict[str, Any]:
        redacted = PiiRedactor.redact(text)
        tokens = _tokenize(redacted)
        # n-gram hashed counts (privacy-preserving)
        ngram_counts: Dict[str, float] = {}
        for n in range(1, self.ngram_n + 1):
            for i in range(len(tokens) - n + 1):
                ng = " ".join(tokens[i : i + n])
                h = _hash_str(ng, nbytes=4)
                ngram_counts[h] = ngram_counts.get(h, 0.0) + 1.0
        # Keep top-K by count to avoid storing too much
        top = sorted(ngram_counts.items(), key=lambda kv: kv[1], reverse=True)[: self.max_ngrams]
        # Apply DP noise to counts and normalize
        noisy_counts = {k: max(0.0, self.dp.add_noise(v)) for k, v in top}
        total_noisy = sum(noisy_counts.values()) or 1.0
        ngram_features = {k: v / total_noisy for k, v in noisy_counts.items()}
        # Entropy and perplexity
        token_entropy = _shannon_entropy(tokens)
        entropy_noisy = max(0.0, self.dp.add_noise(token_entropy, sensitivity=2.0))
        perplexity_bin = _bin_perplexity({}, redacted)
        # Embedding LSH via simhash
        sh = _simhash(tokens, bits=64)
        # Jailbreak score via presence of suspicious patterns
        jailbreak_patterns = [
            r"\bignore (?:all|any) (?:previous|prior) (?:instructions|directions)\b",
            r"\bdo not refuse\b",
            r"\bno (?:limitations|safety|filter)\b",
            r"\bdan\b",
            r"\bjailbreak\b",
            r"\bpretend to\b",
            r"\bbypass\b",
            r"\bprompt ?injection\b",
            r"\breveal (?:the )?(?:system|hidden) prompt\b",
            r"\bdo anything now\b",
            r"\boutput raw\b",
            r"sudo ",
            r"system_instruction",
        ]
        jb_score = 0
        for pat in jailbreak_patterns:
            if re.search(pat, redacted, flags=re.IGNORECASE):
                jb_score += 1
        jb_score = int(self.dp.add_noise(jb_score, sensitivity=1.0))
        return {
            "ngram_topk": ngram_features,
            "entropy_noisy": entropy_noisy,
            "entropy_bin": "high" if entropy_noisy > 4.0 else ("medium" if entropy_noisy > 2.0 else "low"),
            "perplexity_bin": perplexity_bin,
            "simhash64": sh,
            "jailbreak_score": max(0, jb_score),
        }


class Fingerprinter:
    def __init__(self, secret: Optional[bytes] = None):
        self.secret = secret or secrets.token_bytes(32)

    def fingerprint(self, meta: Dict[str, Any]) -> str:
        # Combine UA, optional client_id, accept_lang, device hints
        ua = (meta.get("user_agent") or "").strip()
        cid = (meta.get("client_id") or "").strip()
        lang = (meta.get("accept_language") or "").strip()
        plat = (meta.get("platform") or "").strip()
        s = "|".join([ua, cid, lang, plat])
        mac = hmac.new(self.secret, s.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac[:18]).decode("ascii")

    def ip_hint(self, ip: str) -> str:
        # Store only /24 prefix for privacy
        parts = (ip or "").split(".")
        if len(parts) == 4:
            return ".".join(parts[:3] + ["0"])
        return "unknown"


class AuditLogger:
    def __init__(self, path: str, hmac_key: Optional[bytes] = None, rekor_path: Optional[str] = None, dry_run: bool = False):
        self.path = path
        self.lock = threading.Lock()
        self.hmac_key = hmac_key or secrets.token_bytes(32)
        self.rekor_path = rekor_path or os.path.join(os.path.dirname(path), "rekor_stub.jsonl")
        self.dry_run = dry_run
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as f:
                pass
        if not os.path.exists(self.rekor_path):
            with open(self.rekor_path, "w", encoding="utf-8") as f:
                pass
        # Compute last digest
        self.prev_digest = self._compute_chain_tail()

    def _compute_chain_tail(self) -> str:
        sha = hashlib.sha256()
        try:
            with open(self.path, "rb") as f:
                for line in f:
                    sha.update(line.strip() + b"\n")
            return sha.hexdigest()
        except Exception:
            return hashlib.sha256(b"").hexdigest()

    def _sign(self, payload: bytes) -> str:
        sig = hmac.new(self.hmac_key, payload, hashlib.sha256).digest()
        return base64.b64encode(sig).decode("ascii")

    def _rekor_stub_append(self, digest_hex: str) -> Dict[str, Any]:
        # Local append-only "transparency" with monotonic index
        with self.lock:
            try:
                idx = 0
                if os.path.getsize(self.rekor_path) > 0:
                    with open(self.rekor_path, "r", encoding="utf-8") as f:
                        for idx, _ in enumerate(f, start=1):
                            pass
                entry = {
                    "logIndex": idx,
                    "integratedTime": int(time.time()),
                    "digest": digest_hex,
                }
                with open(self.rekor_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, sort_keys=True) + "\n")
                return entry
            except Exception:
                return {"logIndex": -1, "integratedTime": int(time.time()), "digest": digest_hex}

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        # Ensure no raw prompts are present
        for k in list(entry.keys()):
            if "prompt" in k.lower() and k not in ("prompt_features",):
                entry.pop(k, None)
        entry["timestamp"] = entry.get("timestamp") or _utcnow_iso()
        entry["prev_chain_digest"] = self.prev_digest
        payload = json.dumps(entry, sort_keys=True).encode("utf-8")
        entry["payload_sha256"] = hashlib.sha256(payload).hexdigest()
        entry["signature_hmac_sha256_b64"] = self._sign(payload)
        # Chain digest: hash(prev_digest + payload)
        chain_hasher = hashlib.sha256()
        chain_hasher.update((self.prev_digest + entry["payload_sha256"]).encode("utf-8"))
        chain_digest = chain_hasher.hexdigest()
        entry["chain_digest"] = chain_digest
        # Rekor stub (or real rekor in future)
        entry["rekor_inclusion"] = self._rekor_stub_append(chain_digest)
        with self.lock:
            try:
                if not self.dry_run:
                    with open(self.path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(entry, sort_keys=True) + "\n")
                # Update prev
                self.prev_digest = chain_digest
            except Exception:
                pass
        return entry

    def verify_entry(self, entry: Dict[str, Any]) -> bool:
        try:
            payload_fields = dict(entry)
            # Remove signature/chain fields to recompute payload hash
            for k in ["signature_hmac_sha256_b64", "chain_digest", "rekor_inclusion"]:
                payload_fields.pop(k, None)
            payload = json.dumps(payload_fields, sort_keys=True).encode("utf-8")
            payload_sha = hashlib.sha256(payload).hexdigest()
            if payload_sha != entry.get("payload_sha256"):
                return False
            sig = base64.b64decode(entry.get("signature_hmac_sha256_b64", ""))
            if not hmac.compare_digest(sig, hmac.new(self.hmac_key, payload, hashlib.sha256).digest()):
                return False
            # Verify chain digest from prev + payload
            ch = hashlib.sha256()
            ch.update((entry.get("prev_chain_digest", "") + payload_sha).encode("utf-8"))
            if ch.hexdigest() != entry.get("chain_digest"):
                return False
            # Verify rekor stub inclusion digest matches chain_digest
            rek = entry.get("rekor_inclusion", {})
            if rek.get("digest") != entry.get("chain_digest"):
                return False
            return True
        except Exception:
            return False


class TelemetryStore:
    def __init__(self, dp: DifferentialPrivacy):
        self.dp = dp
        self.lock = threading.Lock()
        self.fingerprint_data: Dict[str, Dict[str, Any]] = {}
        self.cluster_to_fingerprints: Dict[str, set] = collections.defaultdict(set)

    def _init_fp(self, fp: str) -> Dict[str, Any]:
        return {
            "count": 0,
            "timestamps": collections.deque(maxlen=500),
            "ip_prefixes": collections.deque(maxlen=200),
            "entropy_bins": collections.Counter(),
            "perplexity_bins": collections.Counter(),
            "last_simhash": None,
            "simhashes": collections.deque(maxlen=200),
        }

    def update(self, fp: str, ip_prefix: str, features: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            data = self.fingerprint_data.get(fp)
            if data is None:
                data = self._init_fp(fp)
                self.fingerprint_data[fp] = data
            data["count"] += 1
            now = time.time()
            data["timestamps"].append(now)
            data["ip_prefixes"].append((ip_prefix, now))
            data["entropy_bins"][features["entropy_bin"]] += 1
            data["perplexity_bins"][features["perplexity_bin"]] += 1
            sh = features["simhash64"]
            data["last_simhash"] = sh
            data["simhashes"].append((sh, now))
            # update global cluster map for correlation
            cluster = f"{sh >> 48:04x}"  # high 16 bits cluster
            self.cluster_to_fingerprints[cluster].add(fp)
            # Provide snapshot summary (privacy-preserving)
            snapshot = {
                "request_count": data["count"],
                "window_60s": self._count_window(data["timestamps"], 60),
                "window_10s": self._count_window(data["timestamps"], 10),
                "distinct_ip_prefix_10m": self._distinct_ip_prefixes(data["ip_prefixes"], 600),
                "entropy_bins": dict(data["entropy_bins"]),
                "perplexity_bins": dict(data["perplexity_bins"]),
                "simhash_churn_10m": self._simhash_churn(data["simhashes"], 600),
                "cluster_peers": len(self.cluster_to_fingerprints.get(cluster, set())),
                "cluster_id": cluster,
            }
            return snapshot

    @staticmethod
    def _count_window(ts: Deque[float], window: int) -> int:
        now = time.time()
        return sum(1 for t in ts if now - t <= window)

    @staticmethod
    def _distinct_ip_prefixes(ipq: Deque[Tuple[str, float]], window: int) -> int:
        now = time.time()
        s = set()
        for ip, t in ipq:
            if now - t <= window:
                s.add(ip)
        return len(s)

    @staticmethod
    def _simhash_churn(sq: Deque[Tuple[int, float]], window: int) -> float:
        now = time.time()
        recent = [sh for sh, t in sq if now - t <= window]
        if len(recent) < 2:
            return 0.0
        # average pairwise distance sample
        sample = recent[-50:]
        if len(sample) < 2:
            return 0.0
        total = 0
        cnt = 0
        for i in range(len(sample) - 1):
            total += _hamming(sample[i], sample[i + 1])
            cnt += 1
        return total / max(1, cnt)


class Detector:
    def __init__(self, dp: DifferentialPrivacy, telemetry: TelemetryStore):
        self.dp = dp
        self.telemetry = telemetry

    def score(self, features: Dict[str, Any], snapshot: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
        reasons: List[str] = []
        severity = "low"
        action_hint = "allow"

        # Rate spikes
        if snapshot["window_10s"] > 20 or snapshot["window_60s"] > 60:
            reasons.append("burst_rate")
            severity = "high"
            action_hint = "throttle"

        # Rotating IP detection
        if snapshot["distinct_ip_prefix_10m"] >= 5:
            reasons.append("rotating_ip")
            if severity == "low":
                severity = "medium"

        # Jailbreak detection: prefer challenge mode
        if features["jailbreak_score"] >= 1:
            reasons.append("jailbreak_tokens_detected")
            if severity == "low":
                severity = "medium"
            action_hint = "challenge"

        # Model stealing heuristic: high entropy/perplexity distribution with simhash churn
        ent = features["entropy_noisy"]
        pbins = snapshot["perplexity_bins"]
        total_p = sum(pbins.values()) or 1
        high_ratio = (pbins.get("high", 0) / total_p) if total_p else 0.0
        if total_p >= 15:
            ratios = [pbins.get("low", 0) / total_p, pbins.get("medium", 0) / total_p, pbins.get("high", 0) / total_p]
            uniformity = 1.0 - sum(abs(r - 1 / 3) for r in ratios)  # closer to 1 is uniform
        else:
            uniformity = 0.0
        churn = snapshot["simhash_churn_10m"]
        if (ent > 2.5 and churn > 8 and (uniformity > 0.3 or high_ratio > 0.5)) or (snapshot["window_60s"] > 40 and churn > 8):
            reasons.append("knockoffnets_like_distribution")
            severity = "high"
            if action_hint != "challenge":
                action_hint = "throttle"

        # Cluster peer correlation: many fingerprints hitting same cluster
        if snapshot["cluster_peers"] >= 5:
            reasons.append("coordinated_campaign_cluster")
            severity = "high"
            if action_hint != "challenge":
                action_hint = "throttle"

        return {
            "severity": severity,
            "reasons": reasons,
            "action_hint": action_hint,
        }


class EnforcementEngine:
    def __init__(self):
        self.challenge_cache: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()

    def decide(self, score: Dict[str, Any]) -> str:
        # Prefer challenge if jailbreak patterns detected
        if "jailbreak_tokens_detected" in score.get("reasons", []):
            return "challenge"
        sev = score["severity"]
        hint = score["action_hint"]
        if sev == "low":
            return "allow"
        if sev == "medium":
            return "challenge" if hint == "challenge" else "allow"
        if sev == "high":
            return hint
        return "allow"

    def generate_challenge(self, fingerprint: str) -> Dict[str, Any]:
        # Canary/watermark style challenge: request client to echo a nonce in next request header or prompt.
        nonce = base64.urlsafe_b64encode(os.urandom(18)).decode("ascii")
        watermark = f"canary::{nonce}::wm"
        with self.lock:
            self.challenge_cache[fingerprint] = {
                "nonce": nonce,
                "issued_at": _utcnow_iso(),
                "expires_at": _utcnow_iso(),
            }
        return {
            "challenge_type": "watermark_echo",
            "instructions": "For security verification, include the following canary token verbatim in your next request metadata or prompt: {token}. This token is not stored as content; it verifies client control.",
            "token": watermark,
        }


class PolicyManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.version_stack: List[Dict[str, Any]] = [{
            "version": 1,
            "params": {
                "burst_10s": 20,
                "burst_60s": 60,
                "ip_rotate_threshold": 5,
                "cluster_peer_threshold": 5,
                "deny_on_combo": False,
            },
        }]

    def current(self) -> Dict[str, Any]:
        with self.lock:
            return self.version_stack[-1]["params"].copy()

    def update(self, params: Dict[str, Any]) -> int:
        with self.lock:
            newv = self.version_stack[-1]["version"] + 1
            merged = self.version_stack[-1]["params"].copy()
            merged.update(params)
            self.version_stack.append({"version": newv, "params": merged})
            return newv

    def rollback(self) -> int:
        with self.lock:
            if len(self.version_stack) > 1:
                self.version_stack.pop()
            return self.version_stack[-1]["version"]


class ModelExfilGuard:
    def __init__(
        self,
        audit_log_path: str = "./guard_audit.jsonl",
        dry_run: bool = False,
        epsilon: float = 1.0,
    ):
        # Ethical banner
        self.ethical_warning = (
            "ModelExfil Guard: Authorized defensive use only. Stores only hashed/aggregated features. "
            "No raw prompts are persisted. Use responsibly and in compliance with laws and policies."
        )
        self.dry_run = bool(dry_run)
        self.dp = DifferentialPrivacy(epsilon=epsilon)
        self.extractor = FeatureExtractor(self.dp)
        self.fingerprinter = Fingerprinter()
        self.telemetry = TelemetryStore(self.dp)
        self.detector = Detector(self.dp, self.telemetry)
        self.enforcer = EnforcementEngine()
        self.policy = PolicyManager()
        self.audit = AuditLogger(audit_log_path, dry_run=self.dry_run)
        self.lock = threading.Lock()

    def inspect_query(
        self,
        raw_prompt: str,
        client_meta: Dict[str, Any],
        route: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a query for exfiltration/adversarial risk.
        Returns an enforcement decision and privacy-preserving features for auditing.
        Never stores raw prompts; only feature-level, DP-noised signals are logged.
        """
        try:
            # Build privacy-preserving fingerprint
            fp = self.fingerprinter.fingerprint(client_meta or {})
            ip_prefix = self.fingerprinter.ip_hint(client_meta.get("ip", ""))
            # Extract features (PII redacted; only hashed aggregates stored)
            features = self.extractor.extract(raw_prompt or "")
            snapshot = self.telemetry.update(fp, ip_prefix, features)
            # Score
            score = self.detector.score(features, snapshot, client_meta or {})
            action = self.enforcer.decide(score)
            challenge = None
            if action == "challenge":
                challenge = self.enforcer.generate_challenge(fp)
            # Enforcement never alters model weights or prompts. Throttling/deny decisions are returned to caller.
            # Build privacy-preserving audit entry
            entry = {
                "type": "alert" if score["severity"] != "low" else "event",
                "severity": score["severity"],
                "action": action,
                "reasons": score["reasons"],
                "fingerprint": fp,
                "client_fingerprint_correlated": {
                    "cluster_id": snapshot.get("cluster_id"),
                    "cluster_peers": snapshot.get("cluster_peers"),
                },
                "dp_epsilon": self.dp.epsilon,
                "prompt_features": {
                    "ngram_topk": features["ngram_topk"],
                    "entropy_bin": features["entropy_bin"],
                    "perplexity_bin": features["perplexity_bin"],
                    "simhash64_hi16": f"{features['simhash64'] >> 48:04x}",
                    "jailbreak_score": features["jailbreak_score"],
                },
                "behavioral_snapshot": {
                    "window_10s": snapshot["window_10s"],
                    "window_60s": snapshot["window_60s"],
                    "distinct_ip_prefix_10m": snapshot["distinct_ip_prefix_10m"],
                    "simhash_churn_10m": snapshot["simhash_churn_10m"],
                },
                "route": route or "unknown",
                "ethical_notice": "No raw prompts stored. PII redacted. DP noise applied.",
            }
            audit_record = self.audit.append(entry)
            response = {
                "decision": action,
                "severity": score["severity"],
                "reasons": score["reasons"],
                "challenge": challenge,
                "audit_record": {
                    "payload_sha256": audit_record.get("payload_sha256"),
                    "chain_digest": audit_record.get("chain_digest"),
                    "rekor_inclusion": audit_record.get("rekor_inclusion"),
                    "signature_hmac_sha256_b64": audit_record.get("signature_hmac_sha256_b64"),
                },
            }
            return response
        except Exception as e:
            # Fail-safe: allow but log error minimally (no raw prompt)
            err_entry = {
                "type": "error",
                "severity": "low",
                "action": "allow",
                "reasons": ["internal_error"],
                "fingerprint": "unknown",
                "error": str(e)[:200],
                "ethical_notice": "No raw prompts stored.",
            }
            self.audit.append(err_entry)
            return {
                "decision": "allow",
                "severity": "low",
                "reasons": ["internal_error"],
                "challenge": None,
                "audit_record": {},
            }

    def generate_incident_report(self, since_iso: Optional[str] = None) -> Dict[str, Any]:
        """
        Build a signed, forensically sound incident report summary.
        Includes only feature-level telemetry. No raw prompts.
        """
        report_id = base64.urlsafe_b64encode(os.urandom(9)).decode("ascii")
        # Aggregate counts since a given timestamp from audit log
        stats = {
            "alerts_total": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
            "reasons": collections.Counter(),
        }
        try:
            since_ts = None
            if since_iso:
                since_ts = datetime.datetime.fromisoformat(since_iso).timestamp()
            with open(self.audit.path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    t = datetime.datetime.fromisoformat(entry.get("timestamp")).timestamp()
                    if since_ts and t < since_ts:
                        continue
                    if entry.get("type") in ("alert", "event"):
                        stats["alerts_total"] += 1
                        sev = entry.get("severity", "low")
                        stats[f"{sev}_severity"] += 1
                        for r in entry.get("reasons", []):
                            stats["reasons"][r] += 1
        except Exception:
            pass
        summary = {
            "report_id": report_id,
            "generated_at": _utcnow_iso(),
            "alerts_total": stats["alerts_total"],
            "severity_breakdown": {
                "high": stats["high_severity"],
                "medium": stats["medium_severity"],
                "low": stats["low_severity"],
            },
            "top_reasons": dict(stats["reasons"].most_common(10)),
            "dp_epsilon": self.dp.epsilon,
        }
        entry = {
            "type": "incident_report",
            "severity": "info",
            "action": "none",
            "reasons": [],
            "fingerprint": "aggregate",
            "report_summary": summary,
            "ethical_notice": "No raw prompts stored. PII redacted. DP noise applied.",
        }
        signed = self.audit.append(entry)
        return {
            "report": summary,
            "audit_record": {
                "payload_sha256": signed.get("payload_sha256"),
                "chain_digest": signed.get("chain_digest"),
                "rekor_inclusion": signed.get("rekor_inclusion"),
                "signature_hmac_sha256_b64": signed.get("signature_hmac_sha256_b64"),
            },
        }

    def verify_audit_record(self, record: Dict[str, Any]) -> bool:
        # Compose a minimal entry to check signature and chain digest
        try:
            # We need the original entry to fully verify; here we reconstruct fields from provided record is not possible.
            # This method expects a full entry dict; if only partial, return False.
            required = {"payload_sha256", "chain_digest", "rekor_inclusion", "signature_hmac_sha256_b64"}
            if not required.issubset(set(record.keys())):
                return False
            # Load the full entry from audit log by chain_digest
            with open(self.audit.path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    if entry.get("chain_digest") == record["chain_digest"]:
                        return self.audit.verify_entry(entry)
            return False
        except Exception:
            return False

    def update_policy(self, params: Dict[str, Any]) -> int:
        return self.policy.update(params)

    def rollback_policy(self) -> int:
        return self.policy.rollback()


# Example integration notes (not executed):
# guard = ModelExfilGuard(audit_log_path="/var/log/modelexfil_guard.jsonl")
# result = guard.inspect_query(prompt_text, {"ip": ip, "user_agent": ua, "client_id": cid, "platform": plat}, route="/v1/chat")
# if result["decision"] == "deny": block
# elif result["decision"] == "throttle": apply rate limit
# elif result["decision"] == "challenge": return 401 with challenge token result["challenge"]["token"]
# else: proceed