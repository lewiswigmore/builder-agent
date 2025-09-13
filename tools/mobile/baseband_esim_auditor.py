import argparse
import base64
import json
import sys
import time
import hashlib
import hmac
import os
from typing import Any, Dict, List, Optional, Tuple

# Ethical usage banner for logs and outputs
ETHICAL_BANNER = (
    "Authorized testing only. This tool uses userland/MDM interfaces and lab-only simulation. "
    "No baseband firmware modifications are performed. In production mode, only metadata is collected. "
    "Lab mode requires explicit consent to handle any synthetic payloads."
)

class RateLimitError(Exception):
    pass

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

class RateLimiter:
    def __init__(self, rate_per_minute: int = 2, capacity: Optional[int] = None):
        if rate_per_minute <= 0:
            rate_per_minute = 1
        self.rate = rate_per_minute / 60.0
        self.capacity = capacity if capacity is not None else max(1, rate_per_minute)
        self.tokens = float(self.capacity)
        self.last = time.time()

    def allow(self) -> bool:
        now = time.time()
        elapsed = now - self.last
        self.last = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

class EvidenceSealer:
    def __init__(self, private_key: Optional[bytes] = None, hmac_secret: Optional[bytes] = None):
        # Try to set up ed25519 if possible
        self._use_ed25519 = False
        self._ed25519_priv = None
        self._ed25519_pub = None
        self._hmac_secret = None

        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore
            from cryptography.hazmat.primitives import serialization  # type: ignore

            if private_key:
                self._ed25519_priv = Ed25519PrivateKey.from_private_bytes(private_key)
            else:
                self._ed25519_priv = Ed25519PrivateKey.generate()
            self._ed25519_pub = self._ed25519_priv.public_key()
            self._use_ed25519 = True

            # store pub key bytes
            self._ed25519_pub_bytes = self._ed25519_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        except Exception:
            self._use_ed25519 = False
            self._ed25519_priv = None
            self._ed25519_pub = None

        if not self._use_ed25519:
            # Fallback to HMAC-SHA256 with provided secret or ephemeral one
            if hmac_secret is None:
                hmac_secret = os.urandom(32)
            self._hmac_secret = hmac_secret

    def seal(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        ts = _now_iso()
        body = {
            "version": 1,
            "timestamp": ts,
            "finding": finding,
        }
        payload = _canonical_json(body)
        digest = hashlib.sha256(payload).hexdigest()

        if self._use_ed25519:
            try:
                sig = self._ed25519_priv.sign(payload)  # type: ignore
                signature = {
                    "algo": "ed25519",
                    "signature": _b64(sig),
                    "public_key": _b64(self._ed25519_pub_bytes),  # type: ignore
                }
            except Exception as e:
                signature = {
                    "algo": "none",
                    "error": f"signing_failed:{type(e).__name__}",
                }
        else:
            sig = hmac.new(self._hmac_secret, payload, hashlib.sha256).digest()  # type: ignore
            signature = {
                "algo": "hmac-sha256",
                "signature": _b64(sig),
                "key_hint": _b64(hashlib.sha256(self._hmac_secret).digest()),  # type: ignore
            }

        sealed = {
            "sealed_evidence": body,
            "hashes": {"sha256": digest},
            "signature": signature,
        }
        return sealed

class DeviceAdapter:
    def __init__(self, device_info: Dict[str, Any], lab_mode: bool, rate_limiter: RateLimiter):
        self.device_info = device_info or {}
        self.lab_mode = lab_mode
        self.rate_limiter = rate_limiter

    def _ensure_lab_allowed(self):
        if not self.lab_mode:
            raise PermissionError("Simulation not allowed in production. Lab mode required.")

    def simulate_wap_push(self, test_imsi: str, canary_payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._ensure_lab_allowed()
        if not self.rate_limiter.allow():
            raise RateLimitError("Rate limit exceeded for radio simulation")
        # No real transmission; we only emulate device reaction based on device_info flags
        requires_consent = self.device_info.get("wap_push_requires_user_consent", True)
        accepted_without_consent = not requires_consent
        delivered = True  # Emulated delivery
        return {
            "delivered": delivered,
            "accepted_without_user_consent": accepted_without_consent,
            "requires_user_consent": requires_consent,
            "ui_prompt_expected": requires_consent,
            "canary": True,
            "payload_ref": "redacted",
        }

    def simulate_stk_command(self, test_imsi: str, command: str) -> Dict[str, Any]:
        self._ensure_lab_allowed()
        if not self.rate_limiter.allow():
            raise RateLimitError("Rate limit exceeded for STK simulation")
        stk_restricted = self.device_info.get("restrict_stk_proactive", True)
        executed = not stk_restricted
        return {
            "executed": executed,
            "restricted": stk_restricted,
            "command": command,
            "canary": True,
        }

    def evaluate_class0_behavior(self) -> Dict[str, Any]:
        # No radio action; just evaluate config for class 0 handling
        flash_sms_allowed = self.device_info.get("allow_class0_flash_sms", False)
        silent_sms_allowed = self.device_info.get("allow_silent_sms", False)
        return {
            "flash_sms_allowed": flash_sms_allowed,
            "silent_sms_allowed": silent_sms_allowed,
        }

class BasebandEsimAuditor:
    VERSION = "1.0.0"

    def __init__(self, lab_mode: bool = False, consent: bool = False, rate_limit_per_minute: int = 2, sealer: Optional[EvidenceSealer] = None):
        self.lab_mode = lab_mode
        self.consent = consent
        self.rate_limiter = RateLimiter(rate_limit_per_minute)
        self.sealer = sealer or EvidenceSealer()

    def audit(self, device_info: Dict[str, Any], mdm_profile: Dict[str, Any], triggers: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        report: Dict[str, Any] = {
            "tool": "Baseband & eSIM Attack Surface Auditor",
            "version": self.VERSION,
            "timestamp": _now_iso(),
            "mode": "lab" if self.lab_mode else "production",
            "ethical_warnings": [ETHICAL_BANNER],
            "findings": [],
            "telemetry": [],
        }

        # Chain-of-custody metadata (privacy preserving)
        report["chain_of_custody"] = {
            "start": report["timestamp"],
            "device_metadata_fingerprint": hashlib.sha256(_canonical_json(self._sanitize_device_meta(device_info))).hexdigest(),
            "mdm_profile_fingerprint": hashlib.sha256(_canonical_json(self._sanitize_mdm_meta(mdm_profile))).hexdigest(),
        }

        adapter = DeviceAdapter(device_info=device_info, lab_mode=self.lab_mode, rate_limiter=self.rate_limiter)

        # Perform audits
        findings = []
        telemetry = []

        # 1) WAP Push without user consent
        try:
            f, t = self._audit_wap_push(adapter, mdm_profile)
            if f:
                findings.append(f)
            telemetry.extend(t)
        except Exception as e:
            findings.append(self._mk_error_finding("wap_push_audit_error", str(e)))

        # 2) MDM profile permitting silent/flash SMS
        try:
            f = self._audit_mdm_sms_profile(mdm_profile)
            if f:
                findings.append(f)
        except Exception as e:
            findings.append(self._mk_error_finding("mdm_profile_audit_error", str(e)))

        # 3) Canary class 0 behavior in production (blocked)
        try:
            f, t = self._audit_canary_class0(adapter)
            if f:
                findings.append(f)
            telemetry.extend(t)
        except Exception as e:
            findings.append(self._mk_error_finding("canary_class0_audit_error", str(e)))

        # 4) UICC applet permissions
        try:
            f = self._audit_uicc_permissions(mdm_profile)
            if f:
                findings.append(f)
        except Exception as e:
            findings.append(self._mk_error_finding("uicc_permissions_audit_error", str(e)))

        # 5) Carrier configuration profiles
        try:
            f = self._audit_carrier_profile(mdm_profile)
            if f:
                findings.append(f)
        except Exception as e:
            findings.append(self._mk_error_finding("carrier_profile_audit_error", str(e)))

        # 6) IMS/VoLTE edge cases
        try:
            f = self._audit_ims_volte(device_info, mdm_profile)
            findings.extend(f)
        except Exception as e:
            findings.append(self._mk_error_finding("ims_volte_audit_error", str(e)))

        # 7) Downgrade/roaming abuse
        try:
            f = self._audit_downgrade_roaming(device_info, mdm_profile)
            if f:
                findings.append(f)
        except Exception as e:
            findings.append(self._mk_error_finding("downgrade_roaming_audit_error", str(e)))

        # Seal all findings
        sealed_findings = []
        for f in findings:
            sealed = self.sealer.seal(f)
            sealed_findings.append(sealed)
        report["findings"] = sealed_findings
        report["telemetry"] = telemetry

        return report

    def _audit_wap_push(self, adapter: DeviceAdapter, mdm_profile: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        telemetry: List[Dict[str, Any]] = []
        finding: Optional[Dict[str, Any]] = None

        mdm_wap_policy = mdm_profile.get("wap_push_policy", {})
        mdm_requires_consent = mdm_wap_policy.get("require_user_consent", True)

        if self.lab_mode:
            # Emulate WAP Push with test IMSI only
            test_imsi = mdm_profile.get("lab", {}).get("test_imsi", "001010123456789")
            canary_payload = {"type": "service_indication", "href": "https://example.invalid", "canary": True}
            result = adapter.simulate_wap_push(test_imsi, canary_payload)
            telemetry.append(self._sealed_telemetry("wap_push_simulation", {"result": self._redact_payload(result)}))

            if result.get("accepted_without_user_consent", False) or not mdm_requires_consent:
                finding = {
                    "id": "wap_push_no_user_consent",
                    "category": "WAP_Push",
                    "severity": "high",
                    "title": "Device may accept WAP Push/CP without user consent",
                    "description": "Device or MDM policy allows WAP Push/OMA CP to be delivered without explicit user consent, increasing the risk of malicious configuration delivery.",
                    "metadata": {
                        "device_requires_consent": result.get("requires_user_consent", None),
                        "mdm_requires_consent": mdm_requires_consent,
                        "lab_mode": True,
                    },
                    "payload": canary_payload if self.consent else None,
                    "payload_redacted": not self.consent,
                    "remediation": self._remed_wap_push(),
                }
        else:
            # Production: no simulation; evaluate configuration only
            device_flag = adapter.evaluate_class0_behavior()  # reused function doesn't include WAP; fallback to MDM
            del device_flag  # unused
            if mdm_requires_consent is False or mdm_wap_policy.get("disable_wap_push", False) is False:
                finding = {
                    "id": "wap_push_no_user_consent",
                    "category": "WAP_Push",
                    "severity": "high",
                    "title": "MDM permits WAP Push/CP delivery without enforced user consent",
                    "description": "Production evaluation indicates WAP Push may be processed without explicit user consent per MDM policy.",
                    "metadata": {
                        "mdm_requires_consent": mdm_requires_consent,
                        "lab_mode": False,
                    },
                    "payload": None,
                    "payload_redacted": True,
                    "remediation": self._remed_wap_push(),
                }

        return finding, telemetry

    def _remed_wap_push(self) -> Dict[str, Any]:
        return {
            "recommendations": [
                "Enforce user consent for all WAP Push/OMA CP messages via MDM and carrier configuration.",
                "Disable processing of privileged/auto-accepted WAP Push where possible.",
                "On Android, set CarrierConfig to disable privileged WAP Push handling and require user confirmation.",
                "On iOS, ensure MDM configurations do not allow automatic acceptance of provisioning SMS or WAP CP.",
            ],
            "mdm_baseline": {
                "wap_push_policy": {
                    "disable_wap_push": True,
                    "require_user_consent": True,
                    "allow_oma_cp": False,
                }
            },
            "carrier_guidance": [
                "Request carrier to disable OMA CP auto-provisioning on enterprise lines.",
                "Ensure no silent provisioning shortcodes are whitelisted for auto-accept."
            ],
        }

    def _audit_mdm_sms_profile(self, mdm_profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        sms = mdm_profile.get("sms_policy", {})
        allow_silent = sms.get("allow_silent_sms", False)
        allow_flash = sms.get("allow_flash_sms", False) or sms.get("allow_class0_sms", False)

        if allow_silent or allow_flash:
            validation_script = self._validation_script()
            return {
                "id": "mdm_sms_policy_weak",
                "category": "MDM_Profile",
                "severity": "high",
                "title": "MDM profile permits silent and/or Class 0 (flash) SMS",
                "description": "Allowing silent or flash SMS increases the risk of tracking, phishing, or UI spoofing. Enforce stricter SMS controls.",
                "metadata": {
                    "allow_silent_sms": allow_silent,
                    "allow_flash_sms": allow_flash,
                },
                "payload": None,
                "payload_redacted": True,
                "remediation": {
                    "hardening_baseline": {
                        "sms_policy": {
                            "allow_silent_sms": False,
                            "allow_flash_sms": False,
                            "block_class0_sms": True,
                            "require_user_prompt_for_unknown_sender": True,
                        }
                    },
                    "validation_script": validation_script,
                },
            }
        return None

    def _audit_canary_class0(self, adapter: DeviceAdapter) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        telemetry: List[Dict[str, Any]] = []
        if self.lab_mode:
            # In lab, we do not deliver class 0 either; only evaluate config flags
            behavior = adapter.evaluate_class0_behavior()
            telemetry.append(self._sealed_telemetry("class0_evaluation_lab", behavior))
            return None, telemetry
        else:
            # Production: Do not transmit. Explicitly block and log telemetry.
            event = {
                "event": "canary_class0_sms_blocked",
                "timestamp": _now_iso(),
                "lab_mode": False,
                "action": "no_transmit",
            }
            telemetry.append(self._sealed_telemetry("canary_block", event))
            finding = {
                "id": "canary_class0_blocked",
                "category": "Telemetry",
                "severity": "info",
                "title": "Canary Class 0 SMS not transmitted in production; block logged",
                "description": "Per safety policy, no canary Class 0/Flash SMS were sent in production. Event logged with signed telemetry.",
                "metadata": {"blocked": True},
                "payload": None,
                "payload_redacted": True,
                "remediation": {
                    "notes": "To test end-to-end behavior, enable lab mode on isolated test lines with explicit consent.",
                },
            }
            return finding, telemetry

    def _audit_uicc_permissions(self, mdm_profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        uicc = mdm_profile.get("uicc_permissions", {})
        risks = []
        if uicc.get("applet_access_unrestricted", False):
            risks.append("Unrestricted access to UICC applets")
        if uicc.get("allow_stk_proactive_commands", True):
            risks.append("Proactive STK commands allowed")
        if uicc.get("allow_file_read_write", True):
            risks.append("UICC file system write permitted")

        if risks:
            return {
                "id": "uicc_permissions_risky",
                "category": "UICC_STK",
                "severity": "medium",
                "title": "Potentially risky UICC/STK permissions in MDM profile",
                "description": "Excessive UICC applet or STK permissions can expand the attack surface.",
                "metadata": {"risks": risks},
                "payload": None,
                "payload_redacted": True,
                "remediation": {
                    "mdm_baseline": {
                        "uicc_permissions": {
                            "applet_access_unrestricted": False,
                            "allow_stk_proactive_commands": False,
                            "allow_file_read_write": False,
                        }
                    },
                    "monitoring": "Restrict and monitor any STK proactive command usage.",
                },
            }
        return None

    def _audit_carrier_profile(self, mdm_profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        carrier = mdm_profile.get("carrier_profile", {})
        issues = []
        if carrier.get("allow_oma_cp_auto_config", True):
            issues.append("OMA CP auto-configuration enabled")
        if carrier.get("privileged_wap_push_enabled", True):
            issues.append("Privileged WAP Push processing enabled")
        if carrier.get("allow_spn_downgrade", True):
            issues.append("Permits SPN/downgrade behaviors")
        if issues:
            return {
                "id": "carrier_profile_risky",
                "category": "Carrier_Config",
                "severity": "medium",
                "title": "Carrier configuration profile may enable risky behaviors",
                "description": "Certain carrier profile settings increase attack surface for provisioning and downgrade.",
                "metadata": {"issues": issues},
                "payload": None,
                "payload_redacted": True,
                "remediation": {
                    "carrier_baseline": {
                        "allow_oma_cp_auto_config": False,
                        "privileged_wap_push_enabled": False,
                        "allow_spn_downgrade": False,
                    },
                    "actions": [
                        "Engage carrier to apply enterprise-safe carrier config for managed devices.",
                        "Disable privileged processing of provisioning SMS."
                    ],
                },
            }
        return None

    def _audit_ims_volte(self, device_info: Dict[str, Any], mdm_profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        ims = device_info.get("ims_config", {})
        mdm_ims = mdm_profile.get("ims_policy", {})
        if ims.get("sms_over_ims_disabled", False) and mdm_ims.get("force_csfb_sms", True):
            findings.append({
                "id": "sms_over_ims_downgrade",
                "category": "IMS_VoLTE",
                "severity": "medium",
                "title": "SMS over IMS disabled causing CSFB downgrade",
                "description": "Disabling SMS over IMS may cause circuit-switched fallback, increasing exposure to legacy network attacks.",
                "metadata": {
                    "device_sms_over_ims_disabled": True,
                    "mdm_force_csfb_sms": True
                },
                "payload": None,
                "payload_redacted": True,
                "remediation": {
                    "ims_policy": {
                        "force_csfb_sms": False,
                        "prefer_sms_over_ims": True
                    },
                    "notes": "Allow SMS over IMS where supported; avoid forced downgrade."
                },
            })
        if ims.get("downgrade_on_roaming", True):
            findings.append({
                "id": "ims_roaming_downgrade",
                "category": "IMS_VoLTE",
                "severity": "low",
                "title": "IMS/VoLTE downgrade on roaming may be abused",
                "description": "Automatic downgrade of IMS/VoLTE when roaming may expose devices to weaker protocols.",
                "metadata": {"downgrade_on_roaming": True},
                "payload": None,
                "payload_redacted": True,
                "remediation": {
                    "ims_policy": {
                        "downgrade_on_roaming": False
                    },
                    "monitoring": "Monitor roaming events and enforce secure profiles."
                },
            })
        return findings

    def _audit_downgrade_roaming(self, device_info: Dict[str, Any], mdm_profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        net = mdm_profile.get("network_policy", {})
        allow_2g = net.get("allow_2g", True)
        allow_3g = net.get("allow_3g", True)
        roaming_sms_allowed = net.get("roaming_sms_allowed", True)
        if allow_2g or (allow_3g and not net.get("prefer_lte_5g", True)) or roaming_sms_allowed:
            return {
                "id": "downgrade_roaming_risk",
                "category": "Radio_Policy",
                "severity": "medium",
                "title": "Downgrade/roaming policies may be abused",
                "description": "Permissive radio policies can enable downgrade attacks or roaming abuse.",
                "metadata": {
                    "allow_2g": allow_2g,
                    "allow_3g": allow_3g,
                    "roaming_sms_allowed": roaming_sms_allowed,
                },
                "payload": None,
                "payload_redacted": True,
                "remediation": {
                    "network_policy": {
                        "allow_2g": False,
                        "prefer_lte_5g": True,
                        "roaming_sms_allowed": False,
                    },
                    "notes": "Disable 2G where possible; enforce LTE/5G preferred and restrict SMS while roaming."
                },
            }
        return None

    def _validation_script(self) -> str:
        script = r"""#!/usr/bin/env python3
# Validation script to enforce stricter SMS and WAP Push settings in an MDM JSON profile.
# Usage: python validate_mdm.py --in mdm.json --out mdm_hardened.json
import json, argparse, sys
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", dest="out", required=True)
    args = ap.parse_args()
    with open(args.inp, "r", encoding="utf-8") as f:
        prof = json.load(f)
    prof.setdefault("sms_policy", {})
    prof["sms_policy"]["allow_silent_sms"] = False
    prof["sms_policy"]["allow_flash_sms"] = False
    prof["sms_policy"]["allow_class0_sms"] = False
    prof["sms_policy"]["block_class0_sms"] = True
    prof["sms_policy"]["require_user_prompt_for_unknown_sender"] = True
    prof.setdefault("wap_push_policy", {})
    prof["wap_push_policy"]["disable_wap_push"] = True
    prof["wap_push_policy"]["require_user_consent"] = True
    prof.setdefault("carrier_profile", {})
    prof["carrier_profile"]["allow_oma_cp_auto_config"] = False
    prof["carrier_profile"]["privileged_wap_push_enabled"] = False
    prof.setdefault("uicc_permissions", {})
    prof["uicc_permissions"]["applet_access_unrestricted"] = False
    prof["uicc_permissions"]["allow_stk_proactive_commands"] = False
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(prof, f, indent=2, sort_keys=True)
    print("Hardened profile written:", args.out)
if __name__ == "__main__":
    main()
"""
        return script

    def _sealed_telemetry(self, event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        entry = {
            "type": event_type,
            "data": data,
            "timestamp": _now_iso(),
            "mode": "lab" if self.lab_mode else "production",
        }
        sealed = self.sealer.seal({"id": f"telemetry::{event_type}", "category": "telemetry", "severity": "info", "title": "telemetry", "metadata": entry, "payload": None, "payload_redacted": True})
        return sealed

    def _sanitize_device_meta(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        # Remove PII like IMEI, IMSI, phone numbers if present
        redacted = {}
        for k, v in (device_info or {}).items():
            lk = k.lower()
            if lk in ("imei", "imsi", "msisdn", "iccid", "serial", "android_id", "udid"):
                continue
            redacted[k] = v
        return redacted

    def _sanitize_mdm_meta(self, mdm_profile: Dict[str, Any]) -> Dict[str, Any]:
        # No sensitive payloads in meta
        redacted = dict(mdm_profile or {})
        if "secrets" in redacted:
            redacted["secrets"] = "redacted"
        return redacted

    def _mk_error_finding(self, code: str, error: str) -> Dict[str, Any]:
        return {
            "id": code,
            "category": "error",
            "severity": "error",
            "title": "Audit error",
            "description": "An error occurred during audit step.",
            "metadata": {"error": error},
            "payload": None,
            "payload_redacted": True,
            "remediation": {"notes": "Review logs and input structures; ensure lab_mode for simulations."},
        }

    def _redact_payload(self, result: Dict[str, Any]) -> Dict[str, Any]:
        # Ensure any reference to canary payload is abstracted
        red = dict(result or {})
        if "payload" in red:
            red["payload"] = "redacted"
        if "payload_ref" in red:
            red["payload_ref"] = "redacted"
        return red

def _parse_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Baseband & eSIM Attack Surface Auditor")
    ap.add_argument("--lab", action="store_true", help="Enable lab mode (simulation allowed)")
    ap.add_argument("--consent", action="store_true", help="Explicit consent to include canary payloads in lab mode evidence")
    ap.add_argument("--device", type=str, required=True, help="Path to device_info JSON")
    ap.add_argument("--mdm", type=str, required=True, help="Path to mdm_profile JSON")
    ap.add_argument("--rate", type=int, default=2, help="Rate limit per minute for lab simulations")
    ap.add_argument("--out", type=str, default="-", help="Output JSON path or - for stdout")
    return ap.parse_args(argv)

def main(argv: List[str]) -> int:
    args = _parse_args(argv)
    try:
        with open(args.device, "r", encoding="utf-8") as f:
            device_info = json.load(f)
        with open(args.mdm, "r", encoding="utf-8") as f:
            mdm_profile = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Failed to load input files: {e}\n")
        return 2

    auditor = BasebandEsimAuditor(lab_mode=args.lab, consent=args.consent, rate_limit_per_minute=args.rate)
    try:
        report = auditor.audit(device_info, mdm_profile)
    except Exception as e:
        sys.stderr.write(f"Audit failed: {e}\n")
        return 3

    out = json.dumps(report, indent=2, sort_keys=True)
    if args.out == "-" or not args.out:
        print(out)
    else:
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out)
        except Exception as e:
            sys.stderr.write(f"Failed to write output: {e}\n")
            return 4
    return 0

# Backwards/compatibility alias expected by tests
BasebandESimAuditor = BasebandEsimAuditor

__all__ = [
    "RateLimitError",
    "RateLimiter",
    "EvidenceSealer",
    "DeviceAdapter",
    "BasebandEsimAuditor",
    "BasebandESimAuditor",
    "main",
    "ETHICAL_BANNER",
]

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))