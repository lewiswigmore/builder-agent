#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import ipaddress
import json
import os
import struct
import sys
import time
import uuid
import hashlib
import hmac
from collections import defaultdict, namedtuple

# Ethical warning
WARNING = (
    "Use this tool only on networks and traffic you are authorized to monitor. "
    "It analyzes metadata only (no decryption) and emits anonymized, signed alerts. "
    "Ensure compliance with privacy laws and corporate policies."
)

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_NSEC_LE = 0xA1B23C4D
PCAP_NSEC_BE = 0x4D3CB2A1

Flow = namedtuple("Flow", "proto ep_a ep_b")

def now_ts():
    return time.time()

def to_hex(b):
    return base64.b16encode(b).decode("ascii").lower()

def sha256_hex(data: bytes):
    return hashlib.sha256(data).hexdigest()

def load_json(path, default):
    if not path or not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def dump_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)

def load_or_create_bytes(path, size=32):
    if path and os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    b = os.urandom(size)
    if path:
        with open(path, "wb") as f:
            f.write(b)
    return b

def anonymize(salt: bytes, value: str) -> str:
    return hashlib.sha256(salt + value.encode("utf-8")).hexdigest()

def in_cidrs(ip: str, cidrs):
    ipobj = ipaddress.ip_address(ip)
    for net in cidrs:
        if ipobj in net:
            return True
    return False

def parse_allowlist(path):
    cfg = load_json(path, {})
    def to_cidrs(items):
        nets = []
        for x in items or []:
            try:
                nets.append(ipaddress.ip_network(x, strict=False))
            except Exception:
                pass
        return nets
    return {
        "stun_turn_domains": set(cfg.get("stun_turn_domains", [])),
        "stun_turn_ips": to_cidrs(cfg.get("stun_turn_ips", [])),
        "conferencing_domains": set(cfg.get("conferencing_domains", [])),
        "tls_sni_allow": set(cfg.get("tls_sni_allow", [])),
        "pre_approved_ja4": set(cfg.get("pre_approved_ja4", [])),
    }

def cidr_list_str(cidrs):
    return [str(c) for c in cidrs]

class HMACSigner:
    def __init__(self, key_path):
        self.key = load_or_create_bytes(key_path or "", 32)
        self.key_id = sha256_hex(self.key)[:16]
    def sign(self, message_bytes: bytes):
        mac = hmac.new(self.key, message_bytes, hashlib.sha256).digest()
        return {
            "sig_algo": "HMAC-SHA256",
            "key_id": self.key_id,
            "signature": base64.b64encode(mac).decode("ascii"),
        }

class TLSParser:
    # Minimal TLS ClientHello parser for TCP
    def parse_client_hello(self, payload: bytes):
        try:
            if len(payload) < 5 or payload[0] != 0x16 or payload[1] != 0x03:
                return None
            rec_len = (payload[3] << 8) | payload[4]
            if 5 + rec_len > len(payload):
                rec_len = len(payload) - 5
            i = 5
            if i + 4 > len(payload) or payload[i] != 0x01:
                return None
            hs_len = (payload[i+1] << 16) | (payload[i+2] << 8) | payload[i+3]
            i += 4
            if i + 2 > len(payload): return None
            version = payload[i:i+2]
            i += 2
            if i + 32 > len(payload): return None
            i += 32  # random
            if i + 1 > len(payload): return None
            sid_len = payload[i]; i += 1
            i += sid_len
            if i + 2 > len(payload): return None
            cs_len = (payload[i] << 8) | payload[i+1]; i += 2
            ciphers = []
            for j in range(0, cs_len, 2):
                if i + 2 > len(payload): break
                ciphers.append((payload[i] << 8) | payload[i+1])
                i += 2
            if i + 1 > len(payload): return None
            comp_len = payload[i]; i += 1
            i += comp_len
            sni = None
            alpn = []
            exts = []
            sigalgs = []
            groups = []
            if i + 2 <= len(payload):
                ext_len = (payload[i] << 8) | payload[i+1]; i += 2
                end = min(len(payload), i + ext_len)
                while i + 4 <= end:
                    et = (payload[i] << 8) | payload[i+1]; i += 2
                    el = (payload[i] << 8) | payload[i+1]; i += 2
                    ed = payload[i:i+el]; i += el
                    exts.append(et)
                    if et == 0x00 and el >= 5:
                        # server_name
                        try:
                            li = 2
                            while li + 3 <= len(ed):
                                ntyp = ed[li]; ln = (ed[li+1] << 8) | ed[li+2]; li += 3
                                if li + ln > len(ed): break
                                if ntyp == 0:
                                    sni = ed[li:li+ln].decode("utf-8", "ignore")
                                    break
                                li += ln
                        except Exception:
                            pass
                    elif et == 0x10 and el >= 3:
                        # ALPN
                        try:
                            li = 2
                            while li + 1 <= len(ed):
                                ln = ed[li]; li += 1
                                if li + ln > len(ed): break
                                alpn.append(ed[li:li+ln].decode("utf-8", "ignore"))
                                li += ln
                        except Exception:
                            pass
                    elif et == 0x0d and el >= 2:
                        # signature_algorithms
                        try:
                            li = 2
                            while li + 2 <= len(ed):
                                sigalgs.append((ed[li] << 8) | ed[li+1])
                                li += 2
                        except Exception:
                            pass
                    elif et == 0x0a and el >= 2:
                        # supported_groups
                        try:
                            li = 2
                            while li + 2 <= len(ed):
                                groups.append((ed[li] << 8) | ed[li+1])
                                li += 2
                        except Exception:
                            pass
            fp_str = "{}|{}|{}|{}|{}|{}".format(
                ".".join(str(x) for x in version),
                "-".join(str(c) for c in ciphers),
                "-".join(str(e) for e in exts),
                ",".join(alpn),
                "-".join(str(s) for s in sigalgs),
                "-".join(str(g) for g in groups),
            )
            return {"sni": sni, "alpn": alpn, "fp_str": fp_str, "ja4": sha256_hex(fp_str.encode("utf-8"))}
        except Exception:
            return None

class DTLSHeuristic:
    @staticmethod
    def is_dtls_handshake(payload: bytes) -> bool:
        if len(payload) < 13:
            return False
        # DTLS record header: type(1), version(2)==0xFE??, epoch(2), seq(6), length(2)
        if payload[0] != 0x16:
            return False
        if payload[1] != 0xFE:
            return False
        # handshake msg type 1 at byte 13
        # Not strictly needed; we just detect record
        return True
    @staticmethod
    def is_dtls_appdata(payload: bytes) -> bool:
        if len(payload) < 13:
            return False
        return payload[0] == 0x17 and payload[1] == 0xFE

class STUN:
    MAGIC = b"\x21\x12\xa4\x42"
    @staticmethod
    def is_stun(payload: bytes) -> bool:
        if len(payload) < 20:
            return False
        # First two bits must be 00, magic cookie at 4
        if (payload[0] & 0xC0) != 0:
            return False
        return payload[4:8] == STUN.MAGIC
    @staticmethod
    def method(payload: bytes) -> int:
        # 12-bit method, interleaved bits across first two bytes
        if len(payload) < 2:
            return -1
        m = ((payload[0] & 0x3E) << 6) | (payload[1] & 0xEF)
        return m
    @staticmethod
    def txid(payload: bytes) -> bytes:
        if len(payload) < 20:
            return b""
        return payload[8:20]
    @staticmethod
    def method_name(method: int) -> str:
        names = {
            0x0001: "Binding",
            0x0003: "Allocate",
            0x0004: "Refresh",
            0x0008: "CreatePermission",
            0x0009: "ChannelBind",
        }
        return names.get(method, f"m{method}")

class PCAPReader:
    def __init__(self, path):
        self.path = path
        self.endian = "<"
        self.ts_mult = 1e-6
    def __iter__(self):
        return self.read_packets()
    def read_packets(self):
        with open(self.path, "rb") as f:
            gh = f.read(24)
            if len(gh) < 24:
                return
            magic = struct.unpack("<I", gh[:4])[0]
            if magic == PCAP_MAGIC_LE:
                self.endian = "<"; self.ts_mult = 1e-6
            elif magic == PCAP_MAGIC_BE:
                self.endian = ">"; self.ts_mult = 1e-6
            elif magic == PCAP_NSEC_LE:
                self.endian = "<"; self.ts_mult = 1e-9
            elif magic == PCAP_NSEC_BE:
                self.endian = ">"; self.ts_mult = 1e-9
            else:
                # Not supported
                return
            ph_fmt = self.endian + "IIII"
            eth_type_ip = 0x0800
            while True:
                ph = f.read(16)
                if len(ph) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(ph_fmt, ph)
                pkt = f.read(incl_len)
                if len(pkt) < 14:
                    continue
                ts = ts_sec + ts_usec * self.ts_mult
                eth_type = (pkt[12] << 8) | pkt[13]
                if eth_type != eth_type_ip:
                    continue
                iphdr = pkt[14:]
                if len(iphdr) < 20:
                    continue
                vihl = iphdr[0]
                version = vihl >> 4
                ihl = (vihl & 0xF) * 4
                if version != 4 or len(iphdr) < ihl + 8:
                    continue
                total_len = (iphdr[2] << 8) | iphdr[3]
                proto = iphdr[9]
                src_ip = ".".join(str(b) for b in iphdr[12:16])
                dst_ip = ".".join(str(b) for b in iphdr[16:20])
                payload = iphdr[ihl: total_len]
                if proto == 17 and len(payload) >= 8:
                    src_port = (payload[0] << 8) | payload[1]
                    dst_port = (payload[2] << 8) | payload[3]
                    upayload = payload[8:]
                    yield {"ts": ts, "proto": "UDP", "src": src_ip, "sp": src_port, "dst": dst_ip, "dp": dst_port, "payload": upayload}
                elif proto == 6 and len(payload) >= 20:
                    src_port = (payload[0] << 8) | payload[1]
                    dst_port = (payload[2] << 8) | payload[3]
                    doff = ((payload[12] >> 4) & 0xF) * 4
                    tpayload = payload[doff:] if len(payload) >= doff else b""
                    yield {"ts": ts, "proto": "TCP", "src": src_ip, "sp": src_port, "dst": dst_ip, "dp": dst_port, "payload": tpayload}

class Hunter:
    def __init__(self, allowlist, baseline_path, out_path, salt_path, key_path, learning_minutes=30, debug=False):
        self.allowlist = allowlist
        self.baseline_path = baseline_path
        self.out_path = out_path
        self.debug = debug
        self.salt = load_or_create_bytes(salt_path or "", 32)
        self.signer = HMACSigner(key_path or "")
        self.baseline = load_json(baseline_path, {"entries": {}, "first_seen": now_ts()})
        self.tls_parser = TLSParser()
        # Runtime state
        self.flows = {}  # key -> dict
        self.host_stun = defaultdict(lambda: {"dests": set(), "txids": defaultdict(int), "count": 0, "retries": 0, "first_ts": None, "last_ts": None})
        self.alerts = []
    def flow_key(self, proto, src, sp, dst, dp):
        a = (src, sp); b = (dst, dp)
        if a <= b:
            return Flow(proto, a, b)
        else:
            return Flow(proto, b, a)
    def update_flow(self, key, ts, payload, direction_ab=True):
        st = self.flows.get(key)
        if not st:
            st = {
                "proto": key.proto,
                "a": key.ep_a, "b": key.ep_b,
                "first_ts": ts, "last_ts": ts,
                "pkt": 0, "bytes": 0,
                "sizes": [],
                "times": [],
                "last_pkt_ts": None,
                "dtls_handshake": False,
                "dtls_appdata": 0,
                "stun_seen": False,
                "turn_methods": set(),
                "tls_ja4": None,
                "tls_sni": None,
                "webrtc_like": False,
                "dirs": {True: 0, False: 0},
            }
            self.flows[key] = st
        st["pkt"] += 1
        st["bytes"] += len(payload)
        st["last_ts"] = ts
        st["dirs"][direction_ab] += 1
        if st["last_pkt_ts"] is not None:
            st["times"].append(max(0.0, ts - st["last_pkt_ts"]))
        st["last_pkt_ts"] = ts
        if st["proto"] == "UDP":
            if STUN.is_stun(payload):
                st["stun_seen"] = True
                method = STUN.method(payload)
                st["turn_methods"].add(method)
                # host STUN state by origin (src of packet)
                origin = self._endpoint_from_dir(key, direction_ab, origin=True)
                dest = self._endpoint_from_dir(key, direction_ab, origin=False)
                hst = self.host_stun[origin[0]]
                hst["dests"].add(dest)
                txid = STUN.txid(payload)
                hst["txids"][txid] += 1
                if hst["first_ts"] is None:
                    hst["first_ts"] = ts
                hst["last_ts"] = ts
                hst["count"] += 1
                if hst["txids"][txid] > 1:
                    hst["retries"] += 1
            if DTLSHeuristic.is_dtls_handshake(payload):
                st["dtls_handshake"] = True
                st["webrtc_like"] = True
            elif DTLSHeuristic.is_dtls_appdata(payload):
                st["dtls_appdata"] += 1
                st["webrtc_like"] = True
            if len(payload) > 0:
                st["sizes"].append(len(payload))
        elif st["proto"] == "TCP":
            if len(payload) > 0 and payload[0] == 0x16 and payload[1] == 0x03:
                ch = self.tls_parser.parse_client_hello(payload)
                if ch:
                    st["tls_ja4"] = ch["ja4"]
                    st["tls_sni"] = ch["sni"]
                    # Might be signaling or TURN-over-TLS if later behavior suggests
        return st
    def _endpoint_from_dir(self, key, ab_dir, origin=True):
        # Given direction (True means a->b), return (ip, port) for origin or dest
        src = key.ep_a if ab_dir else key.ep_b
        dst = key.ep_b if ab_dir else key.ep_a
        return src if origin else dst
    def summarize_flow(self, key, st):
        # Stats needed for detection
        return {
            "duration": st["last_ts"] - st["first_ts"],
            "pkt": st["pkt"],
            "bytes": st["bytes"],
            "avg_iat": (sum(st["times"]) / len(st["times"])) if st["times"] else 0.0,
            "size_cv": self._coeff_var(st["sizes"]),
            "unique_sizes": len(set(st["sizes"])),
            "dtls": st["dtls_handshake"],
            "dtls_appdata": st["dtls_appdata"],
            "stun_seen": st["stun_seen"],
            "turn_methods": list(st["turn_methods"]),
            "tls_ja4": st["tls_ja4"],
            "tls_sni": st["tls_sni"],
            "webrtc_like": st["webrtc_like"],
        }
    @staticmethod
    def _coeff_var(values):
        n = len(values)
        if n < 2:
            return 0.0
        mean = sum(values) / n
        if mean == 0:
            return 0.0
        var = sum((x - mean) ** 2 for x in values) / (n - 1)
        return (var ** 0.5) / mean
    def should_allow(self, key, st):
        # Allow if endpoints are in allowlist IPs or tls_sni in allowed or baseline fingerprint approved
        a_ip, a_p = st["a"]
        b_ip, b_p = st["b"]
        if in_cidrs(a_ip, self.allowlist["stun_turn_ips"]) or in_cidrs(b_ip, self.allowlist["stun_turn_ips"]):
            return True
        sni = st.get("tls_sni")
        if sni and (sni in self.allowlist["tls_sni_allow"] or sni in self.allowlist["conferencing_domains"] or sni in self.allowlist["stun_turn_domains"]):
            return True
        # Baseline fingerprints
        fp = self.flow_fingerprint(key, st)
        bl = self.baseline["entries"].get(fp)
        if bl and bl.get("approved", False):
            return True
        return False
    def flow_fingerprint(self, key, st):
        # Build reproducible fingerprint string for baseline
        a_ip, a_p = st["a"]; b_ip, b_p = st["b"]
        elems = [
            st["proto"],
            f"{a_p}-{b_p}",
            "dtls" if st["dtls_handshake"] else "nodtls",
            "stun" if st["stun_seen"] else "nostun",
            "tm:" + "-".join(str(x) for x in sorted(st["turn_methods"])),
            st.get("tls_ja4") or "noja4",
        ]
        return sha256_hex("|".join(elems).encode("utf-8"))
    def update_baseline(self, key, st, ts):
        fp = self.flow_fingerprint(key, st)
        entry = self.baseline["entries"].get(fp)
        if not entry:
            entry = {"first_seen": ts, "count": 0, "approved": False}
            self.baseline["entries"][fp] = entry
        entry["count"] += 1
        # Auto-approve if allowlist domain/ip observed and enough samples
        if not entry["approved"] and self.should_allow(key, st):
            entry["approved"] = True
        return entry
    def detect(self):
        # Build alerts based on aggregated flows
        results = []
        for key, st in self.flows.items():
            sm = self.summarize_flow(key, st)
            ts0 = st["first_ts"]; ts1 = st["last_ts"]
            self.update_baseline(key, st, ts1)
            # 1) Covert exfil over long-lived TURN-relayed DTLS with uniform sizes to unsanctioned endpoints
            if st["proto"] == "UDP" and sm["webrtc_like"] and sm["stun_seen"]:
                is_turn = any(m in (0x0003, 0x0004, 0x0008, 0x0009) for m in st["turn_methods"])
                long_lived = sm["duration"] >= 300
                uniform = (sm["pkt"] >= 50 and sm["size_cv"] <= 0.1 and sm["unique_sizes"] / max(1, sm["pkt"]) <= 0.2)
                allowed = self.should_allow(key, st)
                if is_turn and long_lived and uniform and not allowed:
                    alert = self._build_alert("covert_exfil", key, st, sm, [
                        f"TURN methods observed: {','.join(STUN.method_name(m) for m in st['turn_methods'])}",
                        f"Long-lived flow duration={round(sm['duration'],2)}s",
                        f"Uniform frame sizes: cv={round(sm['size_cv'],3)} unique/total={sm['unique_sizes']}/{sm['pkt']}",
                        "DTLS-SRTP/DataChannel application data observed" if sm["dtls_appdata"] > 0 else "DTLS handshake observed",
                        "Endpoint not in allowlist",
                    ], severity="high", remediation=[
                        "Audit the endpoint for unauthorized P2P tools or exfiltration agents.",
                        "Block or rate-limit unsanctioned TURN relays at egress.",
                        "Compare JA4/DTLS fingerprints against known-good baseline; investigate deviations."
                    ])
                    results.append(alert)
            # 2) Domain-fronted TURN over TLS:443 with atypical ICE retries/candidate churn
            if st["proto"] == "TCP" and ((st["a"][1] == 443 or st["b"][1] == 443) or st["tls_ja4"]):
                sni = st.get("tls_sni")
                allowed_sni = sni and (sni in self.allowlist["tls_sni_allow"] or sni in self.allowlist["stun_turn_domains"] or sni in self.allowlist["conferencing_domains"])
                long_tcp = (sm["duration"] >= 120)
                # Correlate with host STUN churn for either endpoint's IP
                a_ip = st["a"][0]; b_ip = st["b"][0]
                churn_hosts = []
                for h in (a_ip, b_ip):
                    hs = self.host_stun.get(h)
                    if hs and hs["count"] >= 20 and len(hs["dests"]) >= 10 and hs["retries"] >= 10:
                        churn_hosts.append(h)
                if long_tcp and (not allowed_sni) and churn_hosts:
                    alert = self._build_alert("domain_fronted_turn", key, st, sm, [
                        f"TLS:443 long-lived flow with SNI={sni or 'None'} not in allowlist",
                        f"ICE candidate churn: {len(self.host_stun[churn_hosts[0]]['dests'])} unique STUN destinations; retries={self.host_stun[churn_hosts[0]]['retries']}",
                        "Potential domain-fronted TURN or phantom signaling behavior"
                    ], severity="medium", remediation=[
                        "Validate SNI and certificate pinning for TURN/TLS; restrict to sanctioned providers.",
                        "Block access to suspicious 443 endpoints associated with TURN fronting.",
                        "Tune allowlist if this is a sanctioned service."
                    ])
                    results.append(alert)
        # Persist baseline
        if self.baseline_path:
            dump_json(self.baseline_path, self.baseline)
        # Write alerts
        for a in results:
            self.emit_alert(a)
        return results
    def _build_alert(self, atype, key, st, sm, rationale_list, severity="medium", remediation=None):
        a_ip, a_p = st["a"]; b_ip, b_p = st["b"]
        # Privacy-preserving identifiers
        aid = str(uuid.uuid4())
        # Hash identifiers with salt
        h_src = anonymize(self.salt, a_ip + ":" + str(a_p))
        h_dst = anonymize(self.salt, b_ip + ":" + str(b_p))
        # Fingerprints
        dtls_fp = "dtls" if sm["dtls"] else "none"
        stun_fp = sha256_hex((",".join(sorted(STUN.method_name(m) for m in st["turn_methods"]))).encode("utf-8")) if st["turn_methods"] else "none"
        ja4 = st.get("tls_ja4") or "none"
        flow_stats = {
            "duration_s": round(sm["duration"], 3),
            "packets": sm["pkt"],
            "bytes": sm["bytes"],
            "avg_iat_s": round(sm["avg_iat"], 6),
            "size_cv": round(sm["size_cv"], 6),
            "unique_sizes": sm["unique_sizes"],
            "dtls_appdata_pkts": sm["dtls_appdata"],
        }
        body = {
            "id": aid,
            "time_start": dt.datetime.utcfromtimestamp(st["first_ts"]).isoformat() + "Z",
            "time_end": dt.datetime.utcfromtimestamp(st["last_ts"]).isoformat() + "Z",
            "type": atype,
            "severity": severity,
            "hashed_identifiers": {"ep_a": h_src, "ep_b": h_dst},
            "fingerprints": {"ja4": ja4, "dtls": dtls_fp, "stun": stun_fp},
            "flow": {"proto": st["proto"], "ports": [a_p, b_p]},
            "flow_stats": flow_stats,
            "allowlist_hit": self.should_allow(key, st),
            "rationale": rationale_list,
            "remediation": remediation or [],
            "meta": {
                "note": "Metadata-only analysis; no payload decryption performed.",
                "ethics": WARNING,
                "allowlist": {
                    "stun_turn_domains": list(self.allowlist["stun_turn_domains"]),
                    "stun_turn_ips": cidr_list_str(self.allowlist["stun_turn_ips"]),
                },
            },
        }
        sig = self.signer.sign(json.dumps(body, sort_keys=True).encode("utf-8"))
        body.update({"signature": sig})
        return body
    def emit_alert(self, alert):
        if not self.out_path:
            print(json.dumps(alert))
            return
        with open(self.out_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")
        if self.debug:
            print(f"[ALERT] {alert['type']} id={alert['id']} severity={alert['severity']}", file=sys.stderr)

def run():
    ap = argparse.ArgumentParser(description="WebRTC Covert Channel Hunter: STUN/TURN Abuse & P2P Exfil IDS")
    ap.add_argument("--pcap", help="Path to pcap file to analyze (offline).")
    ap.add_argument("--allowlist", help="JSON allowlist file with keys: stun_turn_domains, stun_turn_ips, conferencing_domains, tls_sni_allow, pre_approved_ja4", required=False)
    ap.add_argument("--baseline", help="Path to baseline state JSON (will be created/updated).", default="webrtc_baseline.json")
    ap.add_argument("--out", help="Output alerts JSONL file (default stdout).", default=None)
    ap.add_argument("--salt", help="Path to anonymization salt file (will be created if missing).", default="webrtc_salt.bin")
    ap.add_argument("--key", help="Path to HMAC key file (will be created if missing).", default="webrtc_hmac.key")
    ap.add_argument("--learning-minutes", type=int, default=30, help="Adaptive baselining learning window (minutes).")
    ap.add_argument("--debug", action="store_true", help="Verbose diagnostics to stderr.")
    args = ap.parse_args()

    print(WARNING, file=sys.stderr)

    allowlist = parse_allowlist(args.allowlist) if args.allowlist else parse_allowlist(None)

    hunter = Hunter(allowlist, args.baseline, args.out, args.salt, args.key, args.learning_minutes, args.debug)

    if not args.pcap or not os.path.exists(args.pcap):
        print("Error: --pcap file required for offline analysis.", file=sys.stderr)
        sys.exit(2)

    reader = PCAPReader(args.pcap)
    pkt_count = 0
    first_ts = None
    last_ts = None
    for rec in reader:
        pkt_count += 1
        ts = rec["ts"]
        if first_ts is None: first_ts = ts
        last_ts = ts
        proto = rec["proto"]
        src = rec["src"]; sp = rec["sp"]; dst = rec["dst"]; dp = rec["dp"]
        key = hunter.flow_key(proto, src, sp, dst, dp)
        # Determine direction (True for a->b)
        dir_ab = (src, sp) == key.ep_a
        hunter.update_flow(key, ts, rec["payload"], dir_ab)
        if hunter.debug and pkt_count % 5000 == 0:
            print(f"[DEBUG] Processed {pkt_count} packets...", file=sys.stderr)
    if pkt_count == 0:
        print("No packets analyzed.", file=sys.stderr)
        sys.exit(0)
    # Learning suppression based on time window
    # If within learning window and allowlisted flows, they will be marked approved in baseline; detection inherently checks allowlist/baseline.
    alerts = hunter.detect()
    if hunter.debug:
        print(f"[SUMMARY] Packets={pkt_count} Flows={len(hunter.flows)} Alerts={len(alerts)}", file=sys.stderr)

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)