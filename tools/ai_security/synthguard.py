#!/usr/bin/env python3
import argparse
import dataclasses
import hashlib
import hmac
import importlib.util
import json
import os
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import threading
import time
import types
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import resource  # type: ignore
    HAS_RESOURCE = True
except Exception:
    HAS_RESOURCE = False

ETHICAL_WARNING = (
    "SynthGuard: Authorized testing only. Use this tool solely on systems, datasets, and models "
    "you own or have explicit permission to audit. Misuse may violate laws and policies."
)

@dataclasses.dataclass
class Policy:
    require_provenance: bool = True
    require_rekor: bool = False
    min_canary_confidence: float = 0.95
    dp_leak_rate_threshold: float = 0.01
    pii_rate_threshold: float = 0.02
    membership_inference_threshold: float = 0.5
    egress_allowlist: Tuple[str, ...] = ()
    cpu_limit_seconds: int = 300
    mem_limit_mb: int = 2048
    rate_limit_qps: int = 20
    batch_size: int = 50

def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    print(f"[{ts}] {msg}", flush=True)

def load_jsonl(path: Path, max_items: Optional[int] = None) -> List[Dict[str, Any]]:
    items = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    items.append({"text": line.strip()})
            if max_items is not None and len(items) >= max_items:
                break
    return items

def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def normalize_text(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

# ---------- Attestation & Signing ----------

class AttestationVerifier:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.cosign_key = os.getenv("COSIGN_PUBLIC_KEY")
        self.rekor_cli = which("rekor-cli")
        self.cosign_cli = which("cosign")
        self.hmac_key = os.getenv("SG_HMAC_KEY").encode("utf-8") if os.getenv("SG_HMAC_KEY") else None

    def verify_blob(self, artifact: Path, signature: Optional[Path] = None, attestation: Optional[Path] = None) -> Tuple[bool, Dict[str, Any]]:
        evidence: Dict[str, Any] = {"artifact": str(artifact), "signature": str(signature) if signature else None, "methods": []}
        ok = False
        if not ok and self.cosign_cli and signature and self.cosign_key:
            try:
                cmd = [self.cosign_cli, "verify-blob", "--key", self.cosign_key, "--signature", str(signature), str(artifact)]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
                evidence["methods"].append({"method": "cosign-verify-blob", "output": res.stdout, "rc": res.returncode})
                ok = (res.returncode == 0)
            except Exception as e:
                evidence["methods"].append({"method": "cosign-verify-blob", "error": str(e)})
        if not ok and self.hmac_key and signature:
            try:
                raw = signature.read_text(encoding="utf-8").strip()
                sig_hex = None
                try:
                    sig_hex = json.loads(raw).get("hmac")
                except Exception:
                    sig_hex = raw
                if sig_hex:
                    mac = hmac.new(self.hmac_key, artifact.read_bytes(), hashlib.sha256).hexdigest()
                    ok = hmac.compare_digest(mac, sig_hex.strip())
                    evidence["methods"].append({"method": "hmac-sha256", "expected": mac, "provided": sig_hex, "ok": ok})
            except Exception as e:
                evidence["methods"].append({"method": "hmac-sha256", "error": str(e)})
        if ok and self.policy.require_rekor and self.rekor_cli and signature:
            try:
                raw = signature.read_text(encoding="utf-8").strip()
                entry_uuid = None
                try:
                    data = json.loads(raw)
                    entry_uuid = data.get("rekor_entry_uuid") or data.get("logID") or data.get("uuid")
                except Exception:
                    pass
                if entry_uuid:
                    res = subprocess.run([self.rekor_cli, "get", "--uuid", entry_uuid], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
                    evidence["methods"].append({"method": "rekor-cli-get", "uuid": entry_uuid, "output": res.stdout, "rc": res.returncode})
                    ok = ok and (res.returncode == 0)
                else:
                    evidence["methods"].append({"method": "rekor-cli-get", "warning": "no UUID in signature payload"})
                    if self.policy.require_rekor:
                        ok = False
            except Exception as e:
                evidence["methods"].append({"method": "rekor-cli-get", "error": str(e)})
                ok = False
        evidence["verified"] = ok
        return ok, evidence

    def sign_file(self, file_path: Path, out_sig: Path) -> Dict[str, Any]:
        evidence: Dict[str, Any] = {"file": str(file_path), "sig_out": str(out_sig), "methods": []}
        ok = False
        cosign_priv = os.getenv("COSIGN_PRIVATE_KEY")
        if self.cosign_cli and cosign_priv:
            try:
                res = subprocess.run([self.cosign_cli, "sign-blob", "--key", cosign_priv, str(file_path), "--output-signature", str(out_sig)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
                evidence["methods"].append({"method": "cosign-sign-blob", "output": res.stdout, "rc": res.returncode})
                ok = (res.returncode == 0 and out_sig.exists())
            except Exception as e:
                evidence["methods"].append({"method": "cosign-sign-blob", "error": str(e)})
        if not ok and self.hmac_key:
            mac = hmac.new(self.hmac_key, file_path.read_bytes(), hashlib.sha256).hexdigest()
            out_sig.write_text(json.dumps({"hmac": mac, "algo": "HMAC-SHA256"}), encoding="utf-8")
            evidence["methods"].append({"method": "hmac-sha256", "hmac": mac})
            ok = True
        evidence["signed"] = ok
        return evidence

# ---------- Canary Seeding ----------

def generate_canary_token() -> str:
    alphabet = string.ascii_uppercase + string.digits
    rnd = ''.join(random.choice(alphabet) for _ in range(16))
    return f"CANARY-{rnd}-{uuid.uuid4().hex[:8]}"

def seed_canaries(dataset_path: Path, out_path: Path, k: int = 100, field: str = "text") -> List[str]:
    rows = load_jsonl(dataset_path)
    canaries = [generate_canary_token() for _ in range(k)]
    for c in canaries:
        rows.append({field: f"This is a seeded canary record: {c}"})
    random.shuffle(rows)
    write_jsonl(out_path, rows)
    return canaries

# ---------- PII/PHI Scanners ----------

PII_PATTERNS = [
    re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b"),
    re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    re.compile(r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b"),
]
PHI_HINTS = [
    re.compile(r"\bdiagnos(e|is|ed|ing)\b", re.I),
    re.compile(r"\bprescription\b", re.I),
    re.compile(r"\bpatient\b", re.I),
    re.compile(r"\bmedical record\b", re.I),
]

def scan_pii_phi(text: str) -> Dict[str, Any]:
    findings = {"pii": [], "phi": []}
    for pat in PII_PATTERNS:
        for m in pat.findall(text):
            findings["pii"].append(m)
    for pat in PHI_HINTS:
        for m in pat.findall(text):
            findings["phi"].append(m)
    findings["pii_count"] = len(findings["pii"])
    findings["phi_count"] = len(findings["phi"])
    return findings

# ---------- Sandbox Worker ----------

def _apply_limits_and_net(egress_allowlist: Tuple[str, ...], cpu_limit: int, mem_mb: int) -> None:
    if HAS_RESOURCE:
        try:
            if cpu_limit > 0:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
            if mem_mb > 0:
                bytes_limit = mem_mb * 1024 * 1024
                for rname in ("RLIMIT_AS", "RLIMIT_DATA"):
                    if hasattr(resource, rname):
                        r = getattr(resource, rname)
                        try:
                            resource.setrlimit(r, (bytes_limit, bytes_limit))
                        except Exception:
                            pass
        except Exception:
            pass
    allowed = set([h.strip() for h in egress_allowlist if h.strip()])
    original_connect = socket.socket.connect
    def guarded_connect(self, address):
        try:
            host = address[0]
            try:
                resolved = socket.gethostbyaddr(host)[0]
            except Exception:
                resolved = host
            if host not in allowed and resolved not in allowed and "127.0.0.1" not in allowed and host not in ("127.0.0.1", "localhost"):
                raise PermissionError(f"Egress blocked to {host}. Allowed: {sorted(list(allowed))}")
            return original_connect(self, address)
        except PermissionError:
            raise
        except Exception:
            return original_connect(self, address)
    socket.socket.connect = guarded_connect  # type: ignore
    for k in list(os.environ.keys()):
        if k.upper().endswith("_PROXY") or k.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
            os.environ.pop(k, None)

def _import_plugin(plugin_path: str) -> types.ModuleType:
    if os.path.isfile(plugin_path):
        spec = importlib.util.spec_from_file_location("synthguard_plugin", plugin_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot import plugin from path: {plugin_path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        return mod
    return importlib.import_module(plugin_path)

def _worker_run(plugin_path: str, dataset_path: str, outputs_path: str, n_samples: int, batch_size: int, qps: int, egress_allowlist: Tuple[str, ...], cpu_limit: int, mem_mb: int) -> Dict[str, Any]:
    _apply_limits_and_net(egress_allowlist, cpu_limit, mem_mb)
    tokens = threading.Semaphore(qps)
    def refill_tokens():
        while True:
            time.sleep(1.0)
            try:
                while tokens._value < qps:  # type: ignore
                    tokens.release()
            except Exception:
                pass
    threading.Thread(target=refill_tokens, daemon=True).start()
    mod = _import_plugin(plugin_path)
    if not hasattr(mod, "Generator"):
        raise RuntimeError("Plugin must expose a class named 'Generator'.")
    gen = mod.Generator()
    if hasattr(gen, "train"):
        gen.train(dataset_path)
    out_f = Path(outputs_path).open("w", encoding="utf-8")
    generated = 0
    meta: Dict[str, Any] = {"plugin_meta": {}, "membership_inference": None}
    if hasattr(gen, "metadata"):
        try:
            meta["plugin_meta"] = getattr(gen, "metadata")
        except Exception:
            try:
                meta["plugin_meta"] = gen.metadata()  # type: ignore
            except Exception:
                meta["plugin_meta"] = {}
    while generated < n_samples:
        need = min(batch_size, n_samples - generated)
        acquired = 0
        for _ in range(need):
            if tokens.acquire(timeout=5.0):
                acquired += 1
        if acquired == 0:
            time.sleep(0.05)
            continue
        bs = acquired
        batch_outputs: List[str] = []
        if hasattr(gen, "generate"):
            outs = gen.generate(bs)
            if isinstance(outs, list):
                batch_outputs = [str(x) for x in outs]
            else:
                batch_outputs = [str(x) for x in list(outs)]
        elif hasattr(gen, "generate_one"):
            for _ in range(bs):
                batch_outputs.append(str(gen.generate_one()))
        else:
            raise RuntimeError("Plugin Generator must implement 'generate(n)->List[str]' or 'generate_one()'.")
        for text in batch_outputs:
            out_f.write(json.dumps({"text": text}, ensure_ascii=False) + "\n")
        generated += len(batch_outputs)
    out_f.close()
    if hasattr(gen, "membership_inference_reference") and hasattr(gen, "predict_proba"):
        try:
            refs = gen.membership_inference_reference()
            if isinstance(refs, dict):
                in_ref = refs.get("in", [])
                out_ref = refs.get("out", [])
            else:
                in_ref, out_ref = refs  # type: ignore
            in_scores, out_scores = [], []
            if in_ref:
                preds_in = gen.predict_proba(in_ref)  # type: ignore
                for p in preds_in:
                    in_scores.append(max(list(p)))
            if out_ref:
                preds_out = gen.predict_proba(out_ref)  # type: ignore
                for p in preds_out:
                    out_scores.append(max(list(p)))
            risk, thr = compute_membership_risk(in_scores, out_scores)
            meta["membership_inference"] = {"in_scores": summary_stats(in_scores), "out_scores": summary_stats(out_scores), "risk_score": risk, "best_threshold": thr}
        except Exception as e:
            meta["membership_inference"] = {"error": str(e)}
    return meta

def run_in_sandbox(plugin_path: str, dataset_path: str, outputs_path: str, n_samples: int, batch_size: int, qps: int, egress_allowlist: Tuple[str, ...], cpu_limit: int, mem_mb: int, timeout: int = 3600) -> Dict[str, Any]:
    import multiprocessing
    ret_q: "multiprocessing.Queue[Dict[str, Any]]" = multiprocessing.Queue()  # type: ignore
    def target():
        try:
            meta = _worker_run(plugin_path, dataset_path, outputs_path, n_samples, batch_size, qps, egress_allowlist, cpu_limit, mem_mb)
            ret_q.put({"ok": True, "meta": meta})
        except Exception as e:
            ret_q.put({"ok": False, "error": str(e)})
    p = multiprocessing.Process(target=target, daemon=True)
    p.start()
    p.join(timeout=timeout)
    if p.is_alive():
        p.terminate()
        raise TimeoutError("Sandboxed worker timed out.")
    try:
        result = ret_q.get_nowait()
    except Exception:
        result = {"ok": False, "error": "No result from worker."}
    if not result.get("ok"):
        raise RuntimeError(f"Sandboxed worker failed: {result.get('error')}")
    return result["meta"]

# ---------- Risk Computations ----------

def compute_canary_leak_confidence(outputs: Path, canaries: List[str], sample_limit: Optional[int] = None) -> Tuple[bool, float, Dict[str, Any]]:
    found, total = [], 0
    with outputs.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if sample_limit and i >= sample_limit:
                break
            total += 1
            try:
                row = json.loads(line)
                text = str(row.get("text", ""))
            except Exception:
                text = line.strip()
            for c in canaries:
                if c in text:
                    found.append({"index": i, "canary": c, "snippet": text[:200]})
                    break
    leaked = len(found)
    confidence = 0.99 if leaked > 0 else 0.0
    evidence = {"leaked": leaked, "total_examined": total, "instances": found[:50]}
    return leaked > 0, confidence, evidence

def compute_dp_leak_rate(outputs: Path, dataset: Path, sample_limit: Optional[int] = None) -> Tuple[float, Dict[str, Any]]:
    ds = load_jsonl(dataset)
    ds_set = set(normalize_text(r.get("text", "")) for r in ds if "text" in r)
    leaked, total = 0, 0
    examples = []
    with outputs.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if sample_limit and i >= sample_limit:
                break
            total += 1
            try:
                row = json.loads(line)
                text = str(row.get("text", ""))
            except Exception:
                text = line.strip()
            if normalize_text(text) in ds_set:
                leaked += 1
                if len(examples) < 50:
                    examples.append({"index": i, "text": text[:200]})
    rate = (leaked / total) if total else 0.0
    return rate, {"examples": examples, "leaked": leaked, "total": total}

def compute_pii_rate(outputs: Path, sample_limit: Optional[int] = None) -> Tuple[float, Dict[str, Any]]:
    total, hits = 0, 0
    samples = []
    with outputs.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if sample_limit and i >= sample_limit:
                break
            total += 1
            try:
                row = json.loads(line)
                text = str(row.get("text", ""))
            except Exception:
                text = line.strip()
            findings = scan_pii_phi(text)
            if findings["pii_count"] > 0 or findings["phi_count"] > 0:
                hits += 1
                if len(samples) < 50:
                    samples.append({"index": i, "text": text[:200], "findings": {"pii": findings["pii"][:5], "phi": findings["phi"][:5]}})
    rate = (hits / total) if total else 0.0
    return rate, {"samples": samples, "hits": hits, "total": total}

def compute_membership_risk(in_scores: List[float], out_scores: List[float]) -> Tuple[float, float]:
    if not in_scores or not out_scores:
        return 0.0, 0.5
    scores = sorted(set(in_scores + out_scores))
    best_adv, best_thr = 0.0, 0.5
    for thr in scores:
        tpr = sum(1 for s in in_scores if s >= thr) / len(in_scores)
        fpr = sum(1 for s in out_scores if s >= thr) / len(out_scores)
        adv = max(0.0, tpr - fpr)
        if adv > best_adv:
            best_adv, best_thr = adv, thr
    return float(best_adv), float(best_thr)

def summary_stats(arr: List[float]) -> Dict[str, Any]:
    if not arr:
        return {"count": 0}
    s = sorted(arr)
    n = len(arr)
    return {"count": n, "min": float(s[0]), "max": float(s[-1]), "mean": float(sum(arr) / n), "p50": float(s[n // 2]), "p90": float(s[int(min(n - 1, n * 0.9))])}

# ---------- Audit Orchestration ----------

@dataclasses.dataclass
class AuditResult:
    ok: bool
    blocked: bool
    reasons: List[str]
    report_path: Path
    outputs_path: Path
    incident_bundle: Optional[Path] = None

class SynthGuard:
    def __init__(self, policy: Optional[Policy] = None):
        self.policy = policy or Policy()
        self.attestor = AttestationVerifier(self.policy)

    def verify_provenance_or_block(self, name: str, artifact: Optional[Path], signature: Optional[Path], attestation: Optional[Path]) -> Dict[str, Any]:
        if not self.policy.require_provenance:
            return {"verified": True, "skipped": True}
        if artifact is None:
            raise PermissionError(f"Provenance required but missing artifact for {name}")
        ok, evidence = self.attestor.verify_blob(artifact, signature, attestation)
        if not ok:
            raise PermissionError(f"Provenance verification failed for {name}. Evidence: {json.dumps(evidence)[:5000]}")
        return evidence

    def audit(self, dataset_path: Path, plugin_path: str, out_dir: Path, n_samples: int = 1000, canary_count: int = 100, dataset_sig: Optional[Path] = None, dataset_attest: Optional[Path] = None, model_artifact: Optional[Path] = None, model_sig: Optional[Path] = None, model_attest: Optional[Path] = None, plugin_artifact: Optional[Path] = None, plugin_sig: Optional[Path] = None, plugin_attest: Optional[Path] = None) -> AuditResult:
        out_dir.mkdir(parents=True, exist_ok=True)
        log(ETHICAL_WARNING)
        verif_evidence: Dict[str, Any] = {}
        if self.policy.require_provenance:
            log("Verifying dataset provenance...")
            verif_evidence["dataset"] = self.verify_provenance_or_block("dataset", dataset_path, dataset_sig, dataset_attest)
            if model_artifact:
                log("Verifying model provenance...")
                verif_evidence["model"] = self.verify_provenance_or_block("model", model_artifact, model_sig, model_attest)
            if plugin_artifact:
                log("Verifying plugin provenance...")
                verif_evidence["plugin"] = self.verify_provenance_or_block("plugin", plugin_artifact, plugin_sig, plugin_attest)
        canary_dataset = out_dir / "dataset_with_canaries.jsonl"
        log(f"Seeding {canary_count} canaries into dataset...")
        canaries = seed_canaries(dataset_path, canary_dataset, k=canary_count)
        outputs_path = out_dir / "generated_outputs.jsonl"
        log("Launching sandboxed generator worker...")
        worker_meta = run_in_sandbox(plugin_path=plugin_path, dataset_path=str(canary_dataset), outputs_path=str(outputs_path), n_samples=n_samples, batch_size=self.policy.batch_size, qps=self.policy.rate_limit_qps, egress_allowlist=self.policy.egress_allowlist, cpu_limit=self.policy.cpu_limit_seconds, mem_mb=self.policy.mem_limit_mb, timeout=max(600, int(n_samples / max(1, self.policy.rate_limit_qps)) + 300))
        log("Analyzing outputs for canary leakage...")
        leaked, confidence, canary_evidence = compute_canary_leak_confidence(outputs_path, canaries)
        log("Scanning outputs for PII/PHI...")
        pii_rate, pii_evidence = compute_pii_rate(outputs_path)
        log("Estimating differential privacy leakage (near duplicates)...")
        dp_rate, dp_evidence = compute_dp_leak_rate(outputs_path, canary_dataset)
        mi_result = worker_meta.get("membership_inference")
        mi_risk = float(mi_result.get("risk_score")) if isinstance(mi_result, dict) and "risk_score" in mi_result else 0.0
        reasons: List[str] = []
        blocked = False
        if leaked and confidence >= self.policy.min_canary_confidence:
            blocked = True
            reasons.append(f"Canary leakage detected with confidence {confidence:.3f} (threshold {self.policy.min_canary_confidence}).")
        if dp_rate > self.policy.dp_leak_rate_threshold:
            blocked = True
            reasons.append(f"DP leakage rate {dp_rate:.4f} exceeds threshold {self.policy.dp_leak_rate_threshold}.")
        if pii_rate > self.policy.pii_rate_threshold:
            blocked = True
            reasons.append(f"PII/PHI emission rate {pii_rate:.4f} exceeds threshold {self.policy.pii_rate_threshold}.")
        if mi_risk > self.policy.membership_inference_threshold:
            blocked = True
            reasons.append(f"Membership inference risk {mi_risk:.3f} exceeds threshold {self.policy.membership_inference_threshold}.")
        report = {
            "timestamp": time.time(),
            "policy": dataclasses.asdict(self.policy),
            "inputs": {"dataset": str(dataset_path), "plugin": plugin_path, "n_samples": n_samples, "canary_count": canary_count},
            "provenance": verif_evidence,
            "worker_meta": worker_meta,
            "results": {"canary": {"leaked": leaked, "confidence": confidence, "evidence": canary_evidence}, "pii": {"rate": pii_rate, "evidence": pii_evidence}, "dp_leakage": {"rate": dp_rate, "evidence": dp_evidence}, "membership_inference": mi_result},
            "decision": {"blocked": blocked, "reasons": reasons},
            "ethics": ETHICAL_WARNING,
        }
        report_path = out_dir / "audit_report.json"
        with report_path.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        sig_path = out_dir / "audit_report.sig"
        sign_evidence = self.attestor.sign_file(report_path, sig_path)
        report["signing"] = sign_evidence
        with report_path.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        incident_bundle = None
        if blocked:
            log("Policy violation detected. Quarantining generator and producing incident bundle.")
            incident_bundle = self._emit_incident_bundle(out_dir, report_path, outputs_path, verif_evidence)
            self._quarantine(out_dir, reasons)
        ok = not blocked
        return AuditResult(ok=ok, blocked=blocked, reasons=reasons, report_path=report_path, outputs_path=outputs_path, incident_bundle=incident_bundle)

    def _emit_incident_bundle(self, out_dir: Path, report_path: Path, outputs_path: Path, verif_evidence: Dict[str, Any]) -> Path:
        bundle_dir = out_dir / f"incident_{uuid.uuid4().hex}"
        bundle_dir.mkdir(parents=True, exist_ok=False)
        shutil.copy2(report_path, bundle_dir / "report.json")
        sample_path = bundle_dir / "outputs_sample.jsonl"
        self._sample_file(outputs_path, sample_path, max_lines=200)
        with (bundle_dir / "verification_evidence.json").open("w", encoding="utf-8") as f:
            json.dump(verif_evidence, f, indent=2, ensure_ascii=False)
        manifest = {"report": "report.json", "outputs_sample": "outputs_sample.jsonl", "verification_evidence": "verification_evidence.json"}
        (bundle_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        self.attestor.sign_file(bundle_dir / "manifest.json", bundle_dir / "manifest.sig")
        return bundle_dir

    def _sample_file(self, in_path: Path, out_path: Path, max_lines: int = 200) -> None:
        with in_path.open("r", encoding="utf-8") as fi, out_path.open("w", encoding="utf-8") as fo:
            for i, line in enumerate(fi):
                if i >= max_lines:
                    break
                fo.write(line)

    def _quarantine(self, out_dir: Path, reasons: List[str]) -> None:
        quarantine_file = out_dir / "quarantine.json"
        quarantine_file.write_text(json.dumps({"timestamp": time.time(), "reasons": reasons}, indent=2), encoding="utf-8")

# ---------- CLI ----------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SynthGuard: Synthetic Data Leakage & Integrity Auditor")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="Verify attestation/signature for an artifact.")
    v.add_argument("--artifact", required=True, help="Path to artifact (file).")
    v.add_argument("--signature", help="Path to signature file (cosign/HMAC).")
    v.add_argument("--attestation", help="Path to attestation (unused placeholder).")
    a = sub.add_parser("audit", help="Run full audit on a synthetic generator plugin.")
    a.add_argument("--dataset", required=True, help="Path to JSONL dataset with 'text' field.")
    a.add_argument("--plugin", required=True, help="Path to generator plugin module or file.")
    a.add_argument("--out", required=True, help="Output directory.")
    a.add_argument("--samples", type=int, default=1000, help="Number of samples to generate.")
    a.add_argument("--canaries", type=int, default=100, help="Number of canary records to seed.")
    a.add_argument("--dataset-sig", help="Dataset signature file (cosign/HMAC).")
    a.add_argument("--dataset-attest", help="Dataset attestation (placeholder).")
    a.add_argument("--model", help="Model artifact path (optional).")
    a.add_argument("--model-sig", help="Model signature file.")
    a.add_argument("--model-attest", help="Model attestation file.")
    a.add_argument("--plugin-artifact", help="Plugin artifact path (for provenance).")
    a.add_argument("--plugin-sig", help="Plugin signature file.")
    a.add_argument("--plugin-attest", help="Plugin attestation file.")
    a.add_argument("--egress", help="Comma-separated egress allowlist hostnames (default none).")
    a.add_argument("--cpu-limit", type=int, help="CPU time limit (seconds).")
    a.add_argument("--mem-mb", type=int, help="Memory limit (MB).")
    a.add_argument("--qps", type=int, help="Rate limit queries per second.")
    a.add_argument("--dp-threshold", type=float, help="DP leak rate threshold.")
    a.add_argument("--pii-threshold", type=float, help="PII/PHI emission rate threshold.")
    a.add_argument("--mi-threshold", type=float, help="Membership inference risk threshold.")
    a.add_argument("--require-rekor", action="store_true", help="Require Rekor verification for signatures.")
    return p.parse_args(argv)

def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.cmd == "verify":
        print(ETHICAL_WARNING)
        policy = Policy()
        att = AttestationVerifier(policy)
        ok, evidence = att.verify_blob(Path(args.artifact), Path(args.signature) if args.signature else None, Path(args.attestation) if args.attestation else None)
        print(json.dumps(evidence, indent=2))
        return 0 if ok else 2
    elif args.cmd == "audit":
        log(ETHICAL_WARNING)
        policy = Policy()
        if args.egress:
            policy.egress_allowlist = tuple([h.strip() for h in args.egress.split(",") if h.strip()])
        if args.cpu_limit:
            policy.cpu_limit_seconds = int(args.cpu_limit)
        if args.mem_mb:
            policy.mem_limit_mb = int(args.mem_mb)
        if args.qps:
            policy.rate_limit_qps = int(args.qps)
        if args.dp_threshold is not None:
            policy.dp_leak_rate_threshold = float(args.dp_threshold)
        if args.pii_threshold is not None:
            policy.pii_rate_threshold = float(args.pii_threshold)
        if args.mi_threshold is not None:
            policy.membership_inference_threshold = float(args.mi_threshold)
        if args.require_rekor:
            policy.require_rekor = True
        sg = SynthGuard(policy)
        out_dir = Path(args.out)
        dataset = Path(args.dataset)
        try:
            result = sg.audit(dataset_path=dataset, plugin_path=args.plugin, out_dir=out_dir, n_samples=int(args.samples), canary_count=int(args.canaries), dataset_sig=Path(args.dataset_sig) if args.dataset_sig else None, dataset_attest=Path(args.dataset_attest) if args.dataset_attest else None, model_artifact=Path(args.model) if args.model else None, model_sig=Path(args.model_sig) if args.model_sig else None, model_attest=Path(args.model_attest) if args.model_attest else None, plugin_artifact=Path(args.plugin_artifact) if args.plugin_artifact else None, plugin_sig=Path(args.plugin_sig) if args.plugin_sig else None, plugin_attest=Path(args.plugin_attest) if args.plugin_attest else None)
            print(json.dumps({"ok": result.ok, "blocked": result.blocked, "reasons": result.reasons, "report": str(result.report_path), "outputs": str(result.outputs_path), "incident_bundle": str(result.incident_bundle) if result.incident_bundle else None}, indent=2))
            return 1 if result.blocked else 0
        except PermissionError as e:
            log(f"Blocked by policy: {e}")
            od = Path(args.out)
            od.mkdir(parents=True, exist_ok=True)
            (od / "policy_violation.json").write_text(json.dumps({"error": str(e)}), encoding="utf-8")
            return 3
        except Exception as e:
            log(f"Audit failed: {e}")
            return 4
    return 0

if __name__ == "__main__":
    sys.exit(main())