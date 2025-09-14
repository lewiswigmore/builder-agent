import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import signal
import sqlite3
import threading
import time
import urllib.request
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List


# Ethical warning: This tool is for authorized testing and defensive security purposes only.
# Do not deploy or test against systems or sources you do not own or have explicit permission to audit.


DEFAULT_POLICY = {
    "clock_skew_seconds": 300,
    "rotation_grace_seconds": 86400,
    "block_ttl_seconds": 86400,
    "integrations": {
        "example": {
            "path": "/webhook/example",
            "honey_path": "/honey/example",
            "sig_header": "X-Signature",
            "ts_header": "X-Timestamp",
            "nonce_header": "X-Nonce",
            "algo": "HMAC-SHA256",
            "ip_allowlist": ["127.0.0.1/32", "::1/128"],
            "cn_pins": [],
            "require_mtls": False,
            "secrets": [
                {
                    "id": "v1",
                    "secret": "",  # filled on initialization
                    "state": "current",
                    "created_at": ""
                }
            ],
        }
    },
}


def now_iso() -> str:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}-{secrets.token_hex(4)}")
    with open(tmp, "wb") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    os.chmod(path, mode)


@dataclass
class VerificationResult:
    ok: bool
    reason: Optional[str]
    details: Dict[str, Any]


class WebhookShield:
    def __init__(self, storage_dir: str):
        self.storage = Path(storage_dir)
        self.storage.mkdir(parents=True, exist_ok=True)
        self.db_path = self.storage / "state.db"
        self.audit_log_path = self.storage / "audit.log"
        self.policy_path = self.storage / "policy.json"
        self.forensic_key_path = self.storage / "forensic.key"
        self._db = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_db()
        self.policy = self._load_or_init_policy()
        self._build_path_index()
        self.forensic_key = self._load_or_init_forensic_key()
        self._stop_event = threading.Event()
        self._start_maintenance_threads()
        self._log_startup_banner()

    def _log_startup_banner(self):
        banner = (
            "WebhookShield initialized. Authorized testing only. "
            "Do not attack or probe systems without explicit permission."
        )
        print(banner)

    def _init_db(self):
        with self._db:
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS nonces (
                    nonce TEXT PRIMARY KEY,
                    ts INTEGER NOT NULL
                )
            """
            )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    event TEXT NOT NULL,
                    data TEXT NOT NULL,
                    prev_hash TEXT,
                    hash TEXT NOT NULL,
                    anchor TEXT
                )
            """
            )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS blocked_sources (
                    source TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    ts INTEGER NOT NULL,
                    expires INTEGER NOT NULL
                )
            """
            )
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS schemas (
                    integration TEXT NOT NULL,
                    schema_hash TEXT NOT NULL,
                    schema_json TEXT NOT NULL,
                    ts INTEGER NOT NULL,
                    PRIMARY KEY (integration, schema_hash)
                )
            """
            )

    def _load_or_init_policy(self) -> Dict[str, Any]:
        if self.policy_path.exists():
            with open(self.policy_path, "r", encoding="utf-8") as f:
                policy = json.load(f)
        else:
            policy = DEFAULT_POLICY.copy()
            policy = json.loads(json.dumps(policy))  # deep copy
            # Initialize default secret and timestamps
            for name, integ in policy["integrations"].items():
                secret = b64(secrets.token_bytes(32))
                integ["secrets"][0]["secret"] = secret
                integ["secrets"][0]["created_at"] = now_iso()
            self._save_policy(policy)
        return policy

    def _save_policy(self, policy: Dict[str, Any]) -> None:
        content = json.dumps(policy, indent=2, sort_keys=True).encode("utf-8")
        atomic_write(self.policy_path, content, mode=0o600)
        self.policy = policy
        self._build_path_index()

    def _build_path_index(self):
        self.path_to_integration: Dict[str, Tuple[str, str]] = {}  # path -> (integration, kind)
        for name, integ in self.policy["integrations"].items():
            if "path" in integ:
                self.path_to_integration[integ["path"]] = (name, "normal")
            if "honey_path" in integ and integ["honey_path"]:
                self.path_to_integration[integ["honey_path"]] = (name, "honey")

    def _load_or_init_forensic_key(self) -> bytes:
        if self.forensic_key_path.exists():
            return self.forensic_key_path.read_bytes()
        key = secrets.token_bytes(32)
        atomic_write(self.forensic_key_path, key, mode=0o600)
        return key

    def _start_maintenance_threads(self):
        t1 = threading.Thread(target=self._maintenance_loop, daemon=True)
        t1.start()

    def stop(self):
        self._stop_event.set()
        time.sleep(0.2)
        self._db.close()

    def _maintenance_loop(self):
        while not self._stop_event.is_set():
            try:
                self._prune_nonces()
                self._prune_blocked_sources()
                self._retire_old_secrets()
            except Exception as e:
                # No crash on maintenance failures
                self._append_audit("MAINTENANCE_ERROR", {"error": str(e)})
            self._stop_event.wait(30.0)

    def _prune_nonces(self):
        skew = int(self.policy.get("clock_skew_seconds", 300))
        cutoff = int(time.time()) - skew * 2
        with self._db:
            self._db.execute("DELETE FROM nonces WHERE ts < ?", (cutoff,))

    def _prune_blocked_sources(self):
        now = int(time.time())
        with self._db:
            self._db.execute("DELETE FROM blocked_sources WHERE expires <= ?", (now,))

    def _retire_old_secrets(self):
        changed = False
        now_ts = int(time.time())
        grace = int(self.policy.get("rotation_grace_seconds", 86400))
        for name, integ in self.policy["integrations"].items():
            for s in integ.get("secrets", []):
                if s.get("state") == "grace":
                    try:
                        created = datetime.datetime.fromisoformat(s.get("created_at"))
                    except Exception:
                        continue
                    created_ts = int(created.replace(tzinfo=datetime.timezone.utc).timestamp())
                    if now_ts - created_ts > grace:
                        s["state"] = "retired"
                        changed = True
        if changed:
            self._save_policy(self.policy)

    def _append_audit(self, event: str, data: Dict[str, Any]) -> None:
        ts = int(time.time())
        record = {"ts": ts, "event": event, "data": data}
        # Compute hash chain
        cur = self._db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        prev_hash = row["hash"] if row else None
        canon = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if prev_hash is None:
            preimage = canon
        else:
            preimage = prev_hash.encode("ascii") + b"." + canon
        h = hashlib.sha256(preimage).hexdigest()
        anchor = self._external_anchor(h, ts)
        with self._db:
            self._db.execute(
                "INSERT INTO audit_log (ts, event, data, prev_hash, hash, anchor) VALUES (?, ?, ?, ?, ?, ?)",
                (ts, event, json.dumps(data, sort_keys=True), prev_hash, h, anchor),
            )
        # Also append to plain append-only file
        line = json.dumps(
            {
                "ts": ts,
                "event": event,
                "data": data,
                "prev_hash": prev_hash,
                "hash": h,
                "anchor": anchor,
            },
            sort_keys=True,
        )
        with self._lock:
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _external_anchor(self, record_hash: str, ts: int) -> str:
        # If ANCHOR_URL is set, try a HEAD request to get an external timestamp/nonce header to anchor.
        url = os.environ.get("ANCHOR_URL", "").strip()
        token = f"{record_hash}:{ts}".encode("ascii")
        sig = b64(hmac.new(self.forensic_key, token, hashlib.sha256).digest())
        anchor = {"sig": sig, "alg": "HMAC-SHA256", "ts": ts, "kind": "local"}
        if url:
            try:
                req = urllib.request.Request(url, method="HEAD")
                with urllib.request.urlopen(req, timeout=2) as resp:
                    hdrs = dict(resp.headers)
                    anchor_id = hdrs.get("X-Anchor-Id") or hdrs.get("Date") or ""
                    anchor["kind"] = "http-head"
                    anchor["ref"] = anchor_id
            except Exception as e:
                anchor["error"] = str(e)
        return json.dumps(anchor, sort_keys=True)

    def _is_blocked(self, source: str) -> Optional[str]:
        cur = self._db.execute("SELECT reason FROM blocked_sources WHERE source = ?", (source,))
        row = cur.fetchone()
        return row["reason"] if row else None

    def _block_source(self, source: str, reason: str):
        ttl = int(self.policy.get("block_ttl_seconds", 86400))
        now = int(time.time())
        expires = now + ttl
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO blocked_sources (source, reason, ts, expires) VALUES (?, ?, ?, ?)",
                (source, reason, now, expires),
            )
        self._append_audit("SOURCE_BLOCKED", {"source": source, "reason": reason, "expires": expires})

    def _nonce_seen(self, nonce: str) -> bool:
        cur = self._db.execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,))
        return cur.fetchone() is not None

    def _record_nonce(self, nonce: str):
        with self._db:
            self._db.execute("INSERT OR IGNORE INTO nonces (nonce, ts) VALUES (?, ?)", (nonce, int(time.time())))

    def _cidr_allows(self, ip: str, cidrs: List[str]) -> bool:
        if not cidrs:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for c in cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
                if ip_obj in net:
                    return True
            except ValueError:
                continue
        return False

    def _canonical_message(self, body: bytes, ts: str, nonce: str) -> bytes:
        body_hash = hashlib.sha256(body).hexdigest()
        return f"{ts}|{nonce}|{body_hash}".encode("utf-8")

    def _compute_hmac(self, secret_b64: str, message: bytes, algo: str) -> str:
        key = b64d(secret_b64)
        if algo.upper() == "HMAC-SHA256":
            digest = hmac.new(key, message, hashlib.sha256).digest()
        elif algo.upper() == "HMAC-SHA512":
            digest = hmac.new(key, message, hashlib.sha512).digest()
        else:
            raise ValueError(f"Unsupported HMAC algorithm: {algo}")
        return b64(digest)

    def _get_secrets(self, integration: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        integ = self.policy["integrations"].get(integration)
        if not integ:
            return None, []
        current = None
        candidates: List[Dict[str, Any]] = []
        for s in integ.get("secrets", []):
            if s.get("state") == "current":
                current = s
            if s.get("state") in ("current", "grace"):
                candidates.append(s)
        return current, candidates

    def _rotate_secret(self, integration: str, reason: str) -> Dict[str, Any]:
        integ = self.policy["integrations"].get(integration)
        if not integ:
            raise ValueError("Integration not found for rotation")
        # Mark existing current as grace
        rotated = {}
        for s in integ.get("secrets", []):
            if s.get("state") == "current":
                s["state"] = "grace"
                rotated = s
                break
        # Add new current
        new_version = {
            "id": f"v{int(time.time())}",
            "secret": b64(secrets.token_bytes(32)),
            "state": "current",
            "created_at": now_iso(),
        }
        integ["secrets"].append(new_version)
        self._save_policy(self.policy)
        self._append_audit(
            "ROTATE_SECRET",
            {
                "integration": integration,
                "reason": reason,
                "old_version": rotated.get("id") if rotated else None,
                "new_version": new_version["id"],
            },
        )
        return new_version

    def _schema_shape(self, payload: Any) -> Any:
        # Represent nested dict keys without values
        if isinstance(payload, dict):
            return {k: self._schema_shape(v) for k, v in sorted(payload.items())}
        elif isinstance(payload, list):
            # For list, represent schema of first element if exists
            return [self._schema_shape(payload[0])] if payload else []
        else:
            return type(payload).__name__

    def _check_schema_drift(self, integration: str, body: bytes):
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            return  # not JSON
        shape = self._schema_shape(payload)
        schema_json = json.dumps(shape, sort_keys=True)
        schema_hash = hashlib.sha256(schema_json.encode("utf-8")).hexdigest()
        cur = self._db.execute(
            "SELECT 1 FROM schemas WHERE integration = ? AND schema_hash = ?", (integration, schema_hash)
        )
        if cur.fetchone() is None:
            # New schema observed
            now_ts = int(time.time())
            with self._db:
                self._db.execute(
                    "INSERT OR IGNORE INTO schemas (integration, schema_hash, schema_json, ts) VALUES (?, ?, ?, ?)",
                    (integration, schema_hash, schema_json, now_ts),
                )
            self._append_audit(
                "SCHEMA_DRIFT",
                {"integration": integration, "schema_hash": schema_hash, "schema": json.loads(schema_json)},
            )

    def _seal_incident(self, kind: str, details: Dict[str, Any]) -> str:
        inc_id = f"{kind}-{uuid.uuid4()}"
        bundle = {
            "id": inc_id,
            "kind": kind,
            "ts": int(time.time()),
            "details": details,
        }
        canon = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = b64(hmac.new(self.forensic_key, hashlib.sha256(canon).digest(), hashlib.sha256).digest())
        bundle["signature"] = sig
        bundle["sig_alg"] = "HMAC-SHA256"
        inc_dir = self.storage / "incidents"
        inc_dir.mkdir(parents=True, exist_ok=True)
        atomic_write(inc_dir / f"{inc_id}.json", json.dumps(bundle, indent=2, sort_keys=True).encode("utf-8"))
        self._append_audit("INCIDENT", {"id": inc_id, "kind": kind})
        return inc_id

    def verify_request(
        self,
        integration: str,
        headers: Dict[str, str],
        body: bytes,
        source_ip: str,
        client_cn: Optional[str],
    ) -> VerificationResult:
        integ = self.policy["integrations"].get(integration)
        if not integ:
            return VerificationResult(False, "integration_unknown", {"integration": integration})
        # Blocked source?
        blocked_reason = self._is_blocked(source_ip)
        if blocked_reason:
            self._append_audit(
                "BLOCKED_SOURCE",
                {"source": source_ip, "reason": blocked_reason, "integration": integration},
            )
            return VerificationResult(False, "blocked_source", {"source": source_ip, "reason": blocked_reason})
        # IP allowlist
        allow = self._cidr_allows(source_ip, integ.get("ip_allowlist", []))
        if not allow:
            return VerificationResult(False, "ip_not_allowed", {"source": source_ip})
        # mTLS CN pinning
        if integ.get("require_mtls", False):
            pins = integ.get("cn_pins", [])
            if not client_cn or (pins and client_cn not in pins):
                return VerificationResult(False, "mtls_cn_invalid", {"client_cn": client_cn, "pins": pins})
        # Timestamp and Nonce
        ts_header = integ.get("ts_header", "X-Timestamp")
        nonce_header = integ.get("nonce_header", "X-Nonce")
        sig_header = integ.get("sig_header", "X-Signature")
        algo = integ.get("algo", "HMAC-SHA256")
        ts_val = headers.get(ts_header)
        nonce = headers.get(nonce_header)
        sig = headers.get(sig_header)
        if not ts_val or not nonce or not sig:
            return VerificationResult(
                False,
                "missing_headers",
                {"missing": [h for h, v in [(ts_header, ts_val), (nonce_header, nonce), (sig_header, sig)] if not v]},
            )
        # Validate timestamp window
        try:
            ts_int = int(ts_val)
        except ValueError:
            return VerificationResult(False, "invalid_timestamp", {"ts": ts_val})
        skew = int(self.policy.get("clock_skew_seconds", 300))
        now_ts = int(time.time())
        if abs(now_ts - ts_int) > skew:
            # Replay or out of window
            self._append_audit(
                "REPLAY_DETECTED",
                {
                    "integration": integration,
                    "reason": "timestamp_out_of_window",
                    "source": source_ip,
                    "ts": ts_int,
                    "now": now_ts,
                    "sig": sig,
                    "algo": algo,
                },
            )
            return VerificationResult(False, "replay_timestamp", {"ts": ts_int, "now": now_ts, "sig": sig})
        # Nonce check
        if self._nonce_seen(nonce):
            self._append_audit(
                "REPLAY_DETECTED",
                {"integration": integration, "reason": "nonce_reuse", "source": source_ip, "nonce": nonce, "sig": sig},
            )
            return VerificationResult(False, "replay_nonce", {"nonce": nonce})
        # Signature check
        message = self._canonical_message(body, ts_val, nonce)
        current, candidates = self._get_secrets(integration)
        trace = []
        valid = False
        for s in candidates:
            try_sig = self._compute_hmac(s["secret"], message, algo)
            trace.append({"version": s["id"], "match": hmac.compare_digest(try_sig, sig)})
            if hmac.compare_digest(try_sig, sig):
                valid = True
                break
        if not valid:
            details = {
                "source": source_ip,
                "ts": ts_val,
                "nonce": nonce,
                "presented_sig": sig,
                "algo": algo,
                "trace": trace,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "headers": self._redact_headers(headers),
            }
            inc_id = self._seal_incident("SIGNATURE_INVALID", details)
            self._append_audit(
                "SIGNATURE_INVALID", {"integration": integration, "incident": inc_id, "source": source_ip}
            )
            return VerificationResult(False, "signature_invalid", {"incident": inc_id})
        # All good: record nonce
        self._record_nonce(nonce)
        # Schema drift check
        self._check_schema_drift(integration, body)
        return VerificationResult(True, None, {"integration": integration})

    def handle_honey(self, integration: str, headers: Dict[str, str], body: bytes, source_ip: str, client_cn: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        integ = self.policy["integrations"].get(integration)
        if not integ:
            return 404, {"error": "integration not found"}
        # Untrusted origin if IP not allowed OR CN not pinned when mtls required OR explicitly header contains 'X-External-Test: true'
        untrusted_reasons = []
        if not self._cidr_allows(source_ip, integ.get("ip_allowlist", [])):
            untrusted_reasons.append("ip_not_allowed")
        if integ.get("require_mtls", False):
            pins = integ.get("cn_pins", [])
            if not client_cn or (pins and client_cn not in pins):
                untrusted_reasons.append("mtls_cn_invalid")
        if headers.get("X-External-Test") == "true":
            untrusted_reasons.append("external_test_flag")
        # Always treat honey hits as suspicious; if untrusted reasons present, escalate
        details = {
            "integration": integration,
            "source": source_ip,
            "client_cn": client_cn,
            "reasons": untrusted_reasons or ["honey_hit"],
            "headers": self._redact_headers(headers),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
        inc_id = self._seal_incident("HONEY_HIT", details)
        self._append_audit("HONEY_HIT", {"integration": integration, "incident": inc_id, "source": source_ip})
        # Rotate secret and block source if untrusted
        if untrusted_reasons:
            self._rotate_secret(integration, reason=f"honey_hit_from_untrusted:{','.join(untrusted_reasons)}")
            self._block_source(source_ip, reason="honey_hit_untrusted")
        # Quarantine response
        return 202, {"status": "quarantined", "incident": inc_id}

    def _redact_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        redacted = {}
        for k, v in headers.items():
            kl = k.lower()
            if "authorization" in kl or "secret" in kl or "signature" in kl:
                redacted[k] = "[redacted]"
            else:
                redacted[k] = v
        return redacted

    def handle_request(
        self, path: str, headers: Dict[str, str], body: bytes, source_ip: str, client_cn: Optional[str]
    ) -> Tuple[int, Dict[str, Any]]:
        mapping = self.path_to_integration.get(path)
        if not mapping:
            return 404, {"error": "not found"}
        integration, kind = mapping
        if kind == "honey":
            code, data = self.handle_honey(integration, headers, body, source_ip, client_cn)
            return code, data
        # Normal webhook
        result = self.verify_request(integration, headers, body, source_ip, client_cn)
        if not result.ok:
            reason = result.reason or "rejected"
            if reason.startswith("replay"):
                self._append_audit(
                    "REQUEST_REJECTED", {"integration": integration, "reason": result.reason, "details": result.details}
                )
            return 403, {"error": reason, "details": result.details}
        # Accept
        self._append_audit(
            "ACCEPT",
            {
                "integration": integration,
                "source": source_ip,
                "body_sha256": hashlib.sha256(body).hexdigest(),
            },
        )
        return 200, {"status": "ok"}

    # HTTP server utilities
    def make_handler(self):
        shield = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "WebhookShield/1.0"

            def do_GET(self):
                if self.path == "/health":
                    self._send_json(200, {"status": "healthy"})
                elif self.path == "/policy":
                    # Do not include secrets in plain; redact
                    pol = json.loads(json.dumps(shield.policy))
                    for integ in pol.get("integrations", {}).values():
                        if "secrets" in integ:
                            integ["secrets"] = [{"id": s["id"], "state": s["state"], "created_at": s["created_at"]} for s in integ["secrets"]]
                    self._send_json(200, pol)
                else:
                    self._send_json(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length > 0 else b""
                source_ip = self.client_address[0]
                client_cn = self.headers.get("X-Client-CN") or self.headers.get("X-SSL-Client-CN") or None
                # Honey endpoints and webhook endpoints handled similarly
                code, data = shield.handle_request(self.path, {k: v for k, v in self.headers.items()}, body, source_ip, client_cn)
                self._send_json(code, data)

            def log_message(self, fmt: str, *args):
                # Quiet unless error
                pass

            def _send_json(self, code: int, data: Dict[str, Any]):
                payload = json.dumps(data).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        return Handler

    def serve(self, host: str = "127.0.0.1", port: int = 8080):
        httpd = ThreadingHTTPServer((host, port), self.make_handler())

        def shutdown(signum, frame):
            print("Shutting down WebhookShield...")
            httpd.shutdown()

        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)
        print(f"WebhookShield listening on http://{host}:{port}")
        httpd.serve_forever()


def main():
    storage = os.environ.get("WEBSHIELD_STORAGE", "./webhookshield_state")
    shield = WebhookShield(storage)
    host = os.environ.get("WEBSHIELD_HOST", "127.0.0.1")
    port = int(os.environ.get("WEBSHIELD_PORT", "8080"))
    try:
        shield.serve(host, port)
    finally:
        shield.stop()


if __name__ == "__main__":
    main()