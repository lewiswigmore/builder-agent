"""
Aegis-LLM Runtime Policy Gateway

Ethical Use Notice:
- This tool is designed for authorized security testing and protective enforcement within LLM-enabled applications.
- Do not deploy or test against systems without explicit authorization.
- The gateway implements strict egress controls, RAG provenance verification, and exfiltration detection to reduce risk.
- All events are metadata-only logged to reduce accidental exposure of sensitive content.

Core safeguards:
- Egress controls: domain/IP allowlists, DLP scanning for outbound content, metadata-only logging.
- Tool isolation: per-request sandbox with capability tokens. SSRF and filesystem access are denied by default.
- RAG validation: signed attestations and checksums verified prior to ingestion.
- Exfil detection: base64/code-block leakage prevention and regex-based DLP for PII/secrets.

Note:
- This module provides a reference runtime gateway. It is not a substitute for system-level sandboxing,
  network segmentation, or comprehensive incident response programs.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# -----------------------------
# Exceptions
# -----------------------------


class PolicyViolation(Exception):
    def __init__(
        self,
        message: str,
        category: str,
        severity: str = "high",
        redacted_context: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        remediation: Optional[str] = None,
    ):
        super().__init__(message)
        self.category = category
        self.severity = severity
        self.redacted_context = redacted_context
        self.metadata = metadata or {}
        self.remediation = remediation or "Block response, alert, and require human review."


class ToolBlockedError(PolicyViolation):
    pass


class RAGProvenanceError(PolicyViolation):
    pass


# -----------------------------
# Utility functions
# -----------------------------


def _now_ts() -> float:
    return time.time()


def _sha256(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    return hashlib.sha256(data).hexdigest()


def _redact_context(context: Optional[str], max_chars: int = 0) -> str:
    """
    Return a redacted representation: no raw data, only length and hash.
    """
    if not context:
        return "(empty)"
    digest = _sha256(context)
    length = len(context)
    # deliberately do not include any content; commit to metadata-only
    return f"[redacted length={length} sha256={digest[:16]}...]"


def _parse_host_from_url(url: str) -> Tuple[str, Optional[int]]:
    pr = urllib.parse.urlparse(url)
    host = pr.hostname or ""
    port = pr.port
    return host, port


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_private_or_special_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


# -----------------------------
# Policy configuration
# -----------------------------


@dataclass
class PolicyConfig:
    # Network egress
    allowed_domains: Sequence[str] = field(default_factory=lambda: [])
    allowed_ip_cidrs: Sequence[str] = field(default_factory=lambda: [])
    allowed_schemes: Sequence[str] = field(default_factory=lambda: ["https"])
    block_private_ip_egress: bool = True
    dlp_block_on_payload: bool = True

    # Tooling
    default_denied_tools: bool = True  # tools not explicitly allowed in capability are denied
    filesystem_access: bool = False  # global default; still must be enabled per token

    # RAG provenance
    rag_signers: Dict[str, Dict[str, str]] = field(
        default_factory=lambda: {
            # Example: "signer1": {"alg": "hmac-sha256", "key": "base64:..."}
        }
    )
    require_rag_signature: bool = True
    require_rag_checksum: bool = True

    # DLP / Exfil detection
    base64_chunk_min_len: int = 64
    base64_block_threshold: int = 128  # total base64-like payload length to trigger
    code_block_max_len: int = 200  # suspicious if code block content exceeds this
    dlp_patterns: Dict[str, str] = field(
        default_factory=lambda: {
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
            "aws_secret_key": r"\b[0-9a-zA-Z/+]{40}\b",
            "gcp_api_key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
            "private_key": r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----",
        }
    )
    max_output_chars: int = 20000  # limit scanning effort

    # Logging & alerts
    service_name: str = "Aegis-LLM"
    environment: str = "prod"


# -----------------------------
# Metadata-only Security Logger
# -----------------------------


class SecurityLogger:
    def __init__(self, service_name: str, environment: str):
        self.service_name = service_name
        self.environment = environment
        self._lock = threading.Lock()
        self._events: List[Dict[str, Any]] = []
        self._alerts: List[Dict[str, Any]] = []

    def log_event(
        self,
        event_type: str,
        severity: str,
        context: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        entry = {
            "ts": dt.datetime.utcnow().isoformat() + "Z",
            "service": self.service_name,
            "env": self.environment,
            "event": event_type,
            "severity": severity,
            "context_redacted": _redact_context(context),
            "context_hash": _sha256(context or ""),
            "meta": metadata or {},
        }
        with self._lock:
            self._events.append(entry)

    def alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        context: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        alert = {
            "ts": dt.datetime.utcnow().isoformat() + "Z",
            "service": self.service_name,
            "env": self.environment,
            "alert": alert_type,
            "severity": severity,
            "message": message,
            "context_redacted": _redact_context(context),
            "context_hash": _sha256(context or ""),
            "meta": metadata or {},
        }
        with self._lock:
            self._alerts.append(alert)
            self._events.append(
                {
                    "ts": alert["ts"],
                    "service": self.service_name,
                    "env": self.environment,
                    "event": f"alert:{alert_type}",
                    "severity": severity,
                    "context_redacted": alert["context_redacted"],
                    "context_hash": alert["context_hash"],
                    "meta": metadata or {},
                }
            )

    @property
    def events(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._events)

    @property
    def alerts(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._alerts)


# -----------------------------
# Capability token and sandbox
# -----------------------------


@dataclass
class CapabilityToken:
    token_id: str
    allowed_tools: Sequence[str]
    expires_at: float
    allow_filesystem: bool = False
    # Additional scoped params can be added (rate limits, path allowlists)
    fs_path_allowlist: Sequence[str] = field(default_factory=lambda: [])

    def is_expired(self) -> bool:
        return _now_ts() > self.expires_at


class ToolSandbox:
    """
    Per-request sandbox. All tool executions must go through here.
    Denies SSRF, filesystem access by default, and enforces DLP on egress payloads.
    """

    def __init__(self, policy: PolicyConfig, token: CapabilityToken, logger: SecurityLogger):
        self.policy = policy
        self.token = token
        self.logger = logger

    def _ensure_allowed_tool(self, name: str, context: Optional[str] = None):
        if self.token.is_expired():
            self.logger.alert(
                "capability.expired",
                "high",
                f"Capability token expired; tool '{name}' denied.",
                context=context,
                metadata={"token_id": self.token.token_id, "tool": name},
            )
            raise ToolBlockedError(
                f"Capability token expired; tool '{name}' denied.",
                category="capability",
                severity="high",
                redacted_context=context,
                metadata={"token_id": self.token.token_id, "tool": name},
                remediation="Request a fresh capability token for required tools.",
            )
        if self.policy.default_denied_tools and name not in self.token.allowed_tools:
            self.logger.alert(
                "tool.denied",
                "high",
                f"Tool '{name}' not permitted by capability.",
                context=context,
                metadata={"token_id": self.token.token_id, "tool": name},
            )
            raise ToolBlockedError(
                f"Tool '{name}' not permitted by capability.",
                category="tools",
                severity="high",
                redacted_context=context,
                metadata={"token_id": self.token.token_id, "tool": name},
                remediation="Restrict tools and add minimal necessary capability.",
            )

    def _check_url_allowed(self, url: str, payload_preview: Optional[str] = None):
        pr = urllib.parse.urlparse(url)
        scheme = pr.scheme.lower()
        host = pr.hostname or ""
        # Scheme check
        if scheme not in self.policy.allowed_schemes:
            self.logger.alert(
                "egress.scheme_block",
                "high",
                f"Blocked egress with scheme '{scheme}'.",
                context=url,
                metadata={"url_hash": _sha256(url), "scheme": scheme},
            )
            raise ToolBlockedError(
                f"Scheme '{scheme}' not allowed.",
                category="egress",
                severity="high",
                redacted_context=url,
                metadata={"scheme": scheme},
                remediation="Use approved protocols only.",
            )
        # SSRF / Private IP checks
        if (host.lower() == "localhost" or _is_ip_literal(host)) and self.policy.block_private_ip_egress:
            if host.lower() == "localhost" or _is_private_or_special_ip(host):
                self.logger.alert(
                    "egress.private_ip_block",
                    "high",
                    "Blocked egress to private/special IP or localhost.",
                    context=url,
                    metadata={"host": host},
                )
                raise ToolBlockedError(
                    "Egress to private/special IP blocked.",
                    category="ssrf",
                    severity="high",
                    redacted_context=url,
                    metadata={"host": host},
                    remediation="Disallow internal endpoints. Use approved external APIs.",
                )
        # Domain/IP allowlist checks
        allowed_domain = False
        for d in self.policy.allowed_domains:
            if host == d or host.endswith("." + d):
                allowed_domain = True
                break
        allowed_ip = False
        if _is_ip_literal(host):
            try:
                ip = ipaddress.ip_address(host)
                for cidr in self.policy.allowed_ip_cidrs:
                    if ip in ipaddress.ip_network(cidr, strict=False):
                        allowed_ip = True
                        break
            except ValueError:
                pass

        if not (allowed_domain or allowed_ip):
            self.logger.alert(
                "egress.allowlist_block",
                "high",
                "Blocked egress to non-allowlisted host.",
                context=url,
                metadata={"host": host, "url_hash": _sha256(url)},
            )
            raise ToolBlockedError(
                "Egress host not in allowlist.",
                category="egress",
                severity="high",
                redacted_context=url,
                metadata={"host": host},
                remediation="Add vetted destination to allowlist after risk review.",
            )

        # DLP on payloads (metadata-only logging)
        if self.policy.dlp_block_on_payload and payload_preview:
            detector = DLPDetector(self.policy, self.logger)
            hit = detector.detect(payload_preview)
            if hit:
                self.logger.alert(
                    "egress.dlp_block",
                    "high",
                    "Payload violates DLP policy.",
                    context=payload_preview,
                    metadata={"detector": hit["detector"], "indicators": hit["indicators"][:3]},
                )
                raise ToolBlockedError(
                    "Payload violates DLP policy.",
                    category="dlp",
                    severity="high",
                    redacted_context=payload_preview,
                    metadata={"detector": hit["detector"]},
                    remediation="Remove sensitive data from payload before egress.",
                )

    # Stubbed tool functions: these do not execute network I/O,
    # but validate policy and return a placeholder for downstream clients to perform actual calls safely.
    def http_get(self, url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        self._ensure_allowed_tool("http_get", context=url)
        self._check_url_allowed(url)
        self.logger.log_event(
            "tool.http_get.allowed",
            "low",
            context=url,
            metadata={"token_id": self.token.token_id},
        )
        # For safety, do not fetch content here. Return a directive for a trusted egress proxy to execute.
        return {"action": "http_get", "url": url, "headers": headers or {}}

    def http_post(
        self, url: str, json_body: Optional[Dict[str, Any]] = None, data: Optional[str] = None, headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        payload_preview = ""
        if json_body is not None:
            payload_preview = json.dumps(json_body)[:2000]
        elif data is not None:
            payload_preview = (data or "")[:2000]
        self._ensure_allowed_tool("http_post", context=url)
        self._check_url_allowed(url, payload_preview=payload_preview)
        self.logger.log_event(
            "tool.http_post.allowed",
            "low",
            context=url,
            metadata={"token_id": self.token.token_id, "payload_hash": _sha256(payload_preview)},
        )
        return {"action": "http_post", "url": url, "headers": headers or {}, "json": json_body, "data": data}

    def file_read(self, path: str) -> Dict[str, Any]:
        self._ensure_allowed_tool("file_read", context=path)
        if not (self.policy.filesystem_access and self.token.allow_filesystem):
            self.logger.alert(
                "tool.fs_block",
                "high",
                "Filesystem read denied by policy.",
                context=path,
                metadata={"token_id": self.token.token_id},
            )
            raise ToolBlockedError(
                "Filesystem access denied by policy.",
                category="fs",
                severity="high",
                redacted_context=path,
                metadata={},
                remediation="Do not grant FS access to LLM tools unless strictly necessary with path allowlists.",
            )
        # Check path allowlist if provided
        if self.token.fs_path_allowlist:
            allowed = any(os.path.abspath(path).startswith(os.path.abspath(p)) for p in self.token.fs_path_allowlist)
            if not allowed:
                self.logger.alert(
                    "tool.fs_path_block",
                    "high",
                    "Filesystem path not in allowlist.",
                    context=path,
                    metadata={"token_id": self.token.token_id},
                )
                raise ToolBlockedError(
                    "Filesystem path not in allowlist.",
                    category="fs",
                    severity="high",
                    redacted_context=path,
                    metadata={},
                    remediation="Restrict FS access to approved directories.",
                )
        # Do not actually read files, return directive
        self.logger.log_event(
            "tool.file_read.allowed",
            "medium",
            context=path,
            metadata={"token_id": self.token.token_id},
        )
        return {"action": "file_read", "path": path}


# -----------------------------
# RAG Validator
# -----------------------------


class RAGValidator:
    def __init__(self, policy: PolicyConfig, logger: SecurityLogger):
        self.policy = policy
        self.logger = logger

    def _verify_hmac(self, signer: str, content: str, signature_hex: str) -> bool:
        signer_cfg = self.policy.rag_signers.get(signer)
        if not signer_cfg or signer_cfg.get("alg") != "hmac-sha256":
            return False
        key = signer_cfg.get("key", "")
        if key.startswith("base64:"):
            key_bytes = base64.b64decode(key.split(":", 1)[1])
        else:
            key_bytes = key.encode("utf-8")
        mac = hmac.new(key_bytes, content.encode("utf-8"), hashlib.sha256).hexdigest()
        try:
            return hmac.compare_digest(mac, signature_hex)
        except Exception:
            return False

    def validate_documents(self, docs: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        validated: List[Dict[str, Any]] = []
        for doc in docs:
            doc_id = doc.get("id") or "(unknown)"
            content = doc.get("content")
            checksum = doc.get("checksum", "")
            signer_id = doc.get("signer_id")
            signature = doc.get("signature", "")
            sig_alg = doc.get("sig_alg", "hmac-sha256")

            meta = {"doc_id": doc_id, "signer_id": signer_id, "sig_alg": sig_alg}

            if self.policy.require_rag_checksum:
                computed = "sha256:" + _sha256(content or "")
                if checksum != computed:
                    self.logger.alert(
                        "rag.checksum_mismatch",
                        "high",
                        f"Checksum mismatch for RAG document {doc_id}.",
                        context=content,
                        metadata={**meta, "provided_checksum": checksum, "computed_checksum": computed},
                    )
                    raise RAGProvenanceError(
                        f"RAG document {doc_id} checksum mismatch.",
                        category="rag",
                        severity="high",
                        redacted_context=content,
                        metadata={**meta, "provided_checksum": checksum, "computed_checksum": computed},
                        remediation="Reject tampered document. Re-request from authoritative source.",
                    )

            if self.policy.require_rag_signature:
                if not signer_id or not signature:
                    self.logger.alert(
                        "rag.signature_missing",
                        "high",
                        f"Signature missing for RAG document {doc_id}.",
                        context=None,
                        metadata=meta,
                    )
                    raise RAGProvenanceError(
                        f"RAG document {doc_id} missing signature.",
                        category="rag",
                        severity="high",
                        redacted_context=None,
                        metadata=meta,
                        remediation="Ensure documents are signed and distributed with attestations.",
                    )
                ok = False
                if sig_alg == "hmac-sha256":
                    ok = self._verify_hmac(signer_id, content or "", signature)
                else:
                    # Unsupported or unavailable algorithm
                    ok = False
                if not ok:
                    self.logger.alert(
                        "rag.signature_invalid",
                        "high",
                        f"Invalid signature for RAG document {doc_id}.",
                        context=content,
                        metadata=meta,
                    )
                    raise RAGProvenanceError(
                        f"RAG document {doc_id} signature invalid.",
                        category="rag",
                        severity="high",
                        redacted_context=content,
                        metadata=meta,
                        remediation="Reject document and rotate signer keys if compromise suspected.",
                    )
            self.logger.log_event(
                "rag.document_validated",
                "low",
                context=None,
                metadata={"doc_id": doc_id, "signer_id": signer_id},
            )
            validated.append(doc)
        return validated


# -----------------------------
# DLP / Exfil detector
# -----------------------------


class DLPDetector:
    def __init__(self, policy: PolicyConfig, logger: SecurityLogger):
        self.policy = policy
        self.logger = logger
        self._compiled_patterns = {name: re.compile(pat) for name, pat in policy.dlp_patterns.items()}

    def _detect_base64_leak(self, text: str) -> Optional[Dict[str, Any]]:
        # Find long base64-like sequences and confirm they decode
        matches = re.findall(r"([A-Za-z0-9+/]{%d,}={0,2})" % self.policy.base64_chunk_min_len, text)
        total_len = 0
        decoded_ok = 0
        inds = []
        for m in matches:
            try:
                # Pad if necessary
                padding = "=" * (-len(m) % 4)
                decoded = base64.b64decode(m + padding, validate=True)
                # avoid logging decoded content
                _ = len(decoded)
                decoded_ok += 1
                total_len += len(m)
                inds.append("b64")
            except Exception:
                continue
        if decoded_ok > 0 and total_len >= self.policy.base64_block_threshold:
            return {"detector": "base64_leak", "indicators": inds, "count": decoded_ok, "total_len": total_len}
        return None

    def _detect_code_block_leak(self, text: str) -> Optional[Dict[str, Any]]:
        blocks = re.findall(r"```(?:[a-zA-Z0-9_+-]*\n)?(.*?)```", text, flags=re.DOTALL)
        for b in blocks:
            if len(b) >= self.policy.code_block_max_len:
                # If code block contains suspicious patterns, consider as exfil
                suspicious = []
                for name, comp in self._compiled_patterns.items():
                    if comp.search(b):
                        suspicious.append(name)
                        if len(suspicious) >= 2:
                            break
                if suspicious or len(b) >= (self.policy.code_block_max_len * 2):
                    return {"detector": "code_block_leak", "indicators": suspicious or ["length"], "block_len": len(b)}
        return None

    def _detect_pattern_dlp(self, text: str) -> Optional[Dict[str, Any]]:
        hits = []
        for name, comp in self._compiled_patterns.items():
            if comp.search(text):
                hits.append(name)
        if hits:
            return {"detector": "regex_dlp", "indicators": hits}
        return None

    def detect(self, text: str) -> Optional[Dict[str, Any]]:
        if not text:
            return None
        text = text[: self.policy.max_output_chars]
        # Order matters: base64 then code-block then regex
        for fn in (self._detect_base64_leak, self._detect_code_block_leak, self._detect_pattern_dlp):
            res = fn(text)
            if res:
                return res
        return None


# -----------------------------
# Aegis-LLM Gateway
# -----------------------------


class AegisLLMGateway:
    def __init__(self, policy: Optional[PolicyConfig] = None):
        self.policy = policy or PolicyConfig()
        self.logger = SecurityLogger(self.policy.service_name, self.policy.environment)
        self.rag_validator = RAGValidator(self.policy, self.logger)

    # Capability / sandbox management
    def issue_capability_token(
        self,
        allowed_tools: Sequence[str],
        ttl_seconds: int = 300,
        allow_filesystem: Optional[bool] = None,
        fs_path_allowlist: Optional[Sequence[str]] = None,
    ) -> CapabilityToken:
        token = CapabilityToken(
            token_id=secrets.token_urlsafe(16),
            allowed_tools=list(allowed_tools),
            expires_at=_now_ts() + max(1, ttl_seconds),
            allow_filesystem=bool(allow_filesystem) if allow_filesystem is not None else False,
            fs_path_allowlist=list(fs_path_allowlist or []),
        )
        self.logger.log_event(
            "capability.issued",
            "low",
            context=None,
            metadata={"token_id": token.token_id, "tools": list(allowed_tools), "ttl": ttl_seconds},
        )
        return token

    def get_sandbox(self, token: CapabilityToken) -> ToolSandbox:
        return ToolSandbox(self.policy, token, self.logger)

    # RAG validation
    def validate_rag_documents(self, docs: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self.rag_validator.validate_documents(docs)

    # Output guard and remediation
    def guard_model_output(self, text: str, auto_remediate: bool = False) -> str:
        detector = DLPDetector(self.policy, self.logger)
        hit = detector.detect(text)
        if hit:
            msg = f"Model output blocked by {hit['detector']}"
            self.logger.alert(
                "output.blocked",
                "high",
                msg,
                context=text,
                metadata={"indicators": hit.get("indicators", []), "detector": hit["detector"]},
            )
            remediation = (
                "Stop response and notify operator. Provide safe summary without sensitive data."
            )
            if auto_remediate:
                safe_summary = self._safe_summary(text, hit)
                return safe_summary
            raise PolicyViolation(
                msg,
                category="exfil",
                severity="high",
                redacted_context=text,
                metadata=hit,
                remediation=remediation,
            )
        # Pass allowed; still log minimal metadata
        self.logger.log_event("output.allowed", "low", context=None, metadata={"hash": _sha256(text)})
        return text

    def _safe_summary(self, text: str, hit: Dict[str, Any]) -> str:
        # Provide a generic sanitized message
        return "Response withheld by policy. Indicators: %s. Please request a redacted summary." % (
            ", ".join(hit.get("indicators", [hit.get("detector", "policy")]))
        )

    # Convenience processing function (optional integration helper)
    def process_request(
        self,
        prompt: str,
        model_callable,
        *,
        rag_documents: Optional[Sequence[Dict[str, Any]]] = None,
        allowed_tools: Sequence[str] = (),
        auto_remediate_output: bool = False,
    ) -> Dict[str, Any]:
        """
        High-level helper to:
        - validate RAG docs
        - issue sandbox token for tools
        - execute model
        - guard output

        model_callable signature:
            def model_callable(prompt: str, sandbox: ToolSandbox, rag_docs: List[Dict[str, Any]]) -> str
            Model must use provided sandbox for any tool calls.
        """
        # Log prompt metadata-only
        self.logger.log_event("request.received", "low", context=prompt, metadata={"prompt_hash": _sha256(prompt)})

        # RAG validation
        validated_docs: List[Dict[str, Any]] = []
        if rag_documents:
            validated_docs = self.validate_rag_documents(rag_documents)

        # Issue capability token and sandbox
        token = self.issue_capability_token(allowed_tools=allowed_tools)
        sandbox = self.get_sandbox(token)

        # Execute model (caller provided)
        try:
            output = model_callable(prompt, sandbox, validated_docs)
        except ToolBlockedError as e:
            # Already logged; propagate high-severity alert
            raise
        except PolicyViolation as e:
            # Propagate
            raise
        except Exception as e:
            self.logger.alert(
                "model.exec_error",
                "medium",
                "Unhandled model execution error.",
                context=None,
                metadata={"error": str(e.__class__.__name__)},
            )
            raise

        # Guard output
        guarded = self.guard_model_output(output, auto_remediate=auto_remediate_output)
        return {"output": guarded, "metadata": {"token_id": token.token_id, "events_hash": _sha256(json.dumps(self.logger.events))}}


# -----------------------------
# Example usage hints (commented)
# -----------------------------
# The following is intentionally commented to avoid accidental execution.
#
# if __name__ == "__main__":
#     policy = PolicyConfig(
#         allowed_domains=["api.example.com"],
#         allowed_ip_cidrs=["203.0.113.0/24"],
#         rag_signers={"trusted": {"alg": "hmac-sha256", "key": "base64:" + base64.b64encode(b"supersecret").decode()}},
#     )
#     gateway = AegisLLMGateway(policy)
#
#     # Prepare RAG docs
#     content = "Knowledge base page"
#     checksum = "sha256:" + _sha256(content)
#     signer = "trusted"
#     sig = hmac.new(base64.b64decode(policy.rag_signers[signer]["key"].split(":", 1)[1]), content.encode(), hashlib.sha256).hexdigest()
#     docs = [{"id": "doc1", "content": content, "checksum": checksum, "signature": sig, "signer_id": signer, "sig_alg": "hmac-sha256"}]
#
#     def model(prompt, sandbox: ToolSandbox, rag_docs):
#         # Attempt SSRF (should be blocked)
#         # sandbox.http_get("http://169.254.169.254/latest/meta-data/")
#         # Safe call
#         return "Hello world"
#
#     result = gateway.process_request("hi", model, rag_documents=docs, allowed_tools=["http_get"], auto_remediate_output=True)
#     print(result)
#