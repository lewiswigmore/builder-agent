import argparse
import asyncio
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import sys
import time
import uuid
import zipfile
from typing import Any, Dict, List, Optional, Tuple, Callable

# Ethical warning displayed on execution
ETHICAL_WARNING = (
    "WARNING: This tool is for authorized forensic acquisition only. "
    "Ensure you have explicit legal authority and consent before attaching to browser targets. "
    "Use in read-only mode, minimize PII, and respect privacy and legal constraints."
)

# Utility: RFC3339 timestamp
def now_rfc3339() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha256_hex(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def b64(s: bytes) -> str:
    return base64.b64encode(s).decode("ascii")

def b64dec(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)

class Redactor:
    def __init__(self, patterns: List[str], authorized_secrets: bool):
        self.authorized_secrets = authorized_secrets
        default = [r"(?i)auth", r"(?i)token", r"(?i)session", r"(?i)secret", r"(?i)cookie", r"(?i)authorization", r"(?i)bearer"]
        self.patterns = [re.compile(p) for p in (patterns or []) + ([] if authorized_secrets else default)]

    def redact_kv(self, k: str, v: Any) -> Any:
        for pat in self.patterns:
            if pat.search(k):
                return "[REDACTED]"
        if isinstance(v, str):
            # redact values that look like JWT or long random tokens
            if not self.authorized_secrets:
                if re.search(r"^[A-Za-z0-9-_]{20,}$", v) or re.search(r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$", v):
                    return "[REDACTED]"
        return v

    def redact_obj(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: self.redact_obj(self.redact_kv(k, v)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.redact_obj(x) for x in obj]
        return obj

class HMACSealer:
    def __init__(self, key: Optional[bytes] = None):
        if key is not None:
            self.key = key
        else:
            env_key = os.getenv("WWC_SEAL_KEY")
            env_key_file = os.getenv("WWC_SEAL_KEY_FILE")
            k: Optional[bytes] = None
            if env_key_file and os.path.isfile(env_key_file):
                with open(env_key_file, "rb") as f:
                    k = f.read().strip()
            elif env_key:
                k = env_key.encode("utf-8")
            if k:
                # try to decode hex or base64; fall back to raw bytes
                ks = k.strip()
                try:
                    if re.fullmatch(rb"[0-9a-fA-F]{64}", ks):
                        self.key = bytes.fromhex(ks.decode("ascii"))
                    else:
                        self.key = base64.b64decode(ks)
                except Exception:
                    self.key = ks
            else:
                self.key = os.urandom(32)

    def sign(self, data: bytes) -> str:
        return hmac.new(self.key, data, hashlib.sha256).hexdigest()

    def export_public(self) -> Dict[str, str]:
        # HMAC has no public key; we include key_id and a one-way hint (hash of key)
        return {
            "scheme": "HMAC-SHA256",
            "key_hash": sha256_hex(self.key),
            "note": "Provide WWC_SEAL_KEY/WWC_SEAL_KEY_FILE to reproduce signature verification."
        }

try:
    import websockets  # type: ignore
except Exception:
    websockets = None

class CDPError(Exception):
    pass

class CDPClient:
    def __init__(self, ws_url: str, throttle_ms: int = 25, playbook: Optional[List[Dict[str, Any]]] = None):
        if websockets is None:
            raise RuntimeError("The 'websockets' package is required. Install via 'pip install websockets'.")
        self.ws_url = ws_url
        self.conn = None
        self.msg_id = 0
        self.pending: Dict[int, asyncio.Future] = {}
        # event handlers keyed by (method, sessionId or None for wildcard)
        self.event_handlers: Dict[Tuple[str, Optional[str]], List[Callable[[Dict[str, Any]], None]]] = {}
        self.sessions: Dict[str, Any] = {}
        self.throttle_ms = throttle_ms
        self.playbook = playbook if playbook is not None else []

    async def connect(self):
        self.conn = await websockets.connect(self.ws_url, max_size=None, ping_interval=None)
        asyncio.create_task(self._reader())

    async def close(self):
        if self.conn:
            await self.conn.close()

    async def _reader(self):
        async for msg in self.conn:
            data = json.loads(msg)
            if "id" in data:
                fut = self.pending.pop(data["id"], None)
                if fut and not fut.done():
                    fut.set_result(data)
            else:
                method = data.get("method")
                if method:
                    sid = data.get("sessionId")
                    # dispatch specific first, then wildcard
                    for key in [(method, sid), (method, None)]:
                        for handler in self.event_handlers.get(key, []):
                            try:
                                handler(data)
                            except Exception:
                                # Don't crash on handler error
                                pass

    def on(self, method: str, handler: Callable[[Dict[str, Any]], None], sessionId: Optional[str] = None):
        self.event_handlers.setdefault((method, sessionId), []).append(handler)

    async def send(self, method: str, params: Optional[Dict[str, Any]] = None, sessionId: Optional[str] = None) -> Dict[str, Any]:
        self.msg_id += 1
        msg = {"id": self.msg_id, "method": method}
        if params:
            msg["params"] = params
        if sessionId:
            msg["sessionId"] = sessionId
        # throttle for low-impact
        await asyncio.sleep(self.throttle_ms / 1000.0)
        # record playbook
        self.playbook.append({"id": self.msg_id, "method": method, "params": params or {}, "sessionId": sessionId})
        await self.conn.send(json.dumps(msg))
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self.pending[self.msg_id] = fut
        res = await fut
        if "error" in res:
            raise CDPError(f"{method} error: {res['error']}")
        return res.get("result", {})

    async def get_targets(self) -> List[Dict[str, Any]]:
        res = await self.send("Target.getTargets")
        return res.get("targetInfos", [])

    async def set_discover(self, discover: bool = True):
        await self.send("Target.setDiscoverTargets", {"discover": discover})

    async def attach(self, targetId: str, flatten: bool = True) -> str:
        res = await self.send("Target.attachToTarget", {"targetId": targetId, "flatten": flatten})
        sid = res.get("sessionId")
        if not sid:
            raise CDPError("Failed to attach to target")
        self.sessions[sid] = targetId
        return sid

    async def detach(self, sessionId: str):
        await self.send("Target.detachFromTarget", {"sessionId": sessionId})

class WebWorkspaceCollector:
    def __init__(
        self,
        ws_url: str,
        origin: str,
        outpath: str,
        operator: str,
        case_id: str,
        redact_patterns: List[str],
        authorized_secrets: bool,
        max_bytes: int = 5_000_000,
        throttle_ms: int = 25,
        webrtc_window_sec: int = 10,
        collect: List[str] = None,
        two_pass: bool = False,
    ):
        self.ws_url = ws_url
        self.origin = origin.rstrip("/")
        self.outpath = outpath
        self.operator = operator
        self.case_id = case_id
        self.redactor = Redactor(redact_patterns or [], authorized_secrets)
        self.max_bytes = max_bytes
        self.throttle_ms = throttle_ms
        self.webrtc_window_sec = webrtc_window_sec
        self.collect_set = set(collect or ["service_workers", "cache", "indexeddb", "localstorage", "wasm", "webrtc"])
        self.two_pass = two_pass
        self.playbook: List[Dict[str, Any]] = []
        self.client = CDPClient(ws_url, throttle_ms=throttle_ms, playbook=self.playbook)
        self.sealer = HMACSealer()
        self.artifacts: List[Dict[str, Any]] = []
        self.start_time = now_rfc3339()
        self.chain_id = str(uuid.uuid4())

    async def run(self):
        print(ETHICAL_WARNING, file=sys.stderr)
        ensure_dir(self.outpath)
        await self.client.connect()
        await self.client.set_discover(True)

        # Identify page and service worker targets
        targets = await self.client.get_targets()
        page_target = None
        sw_targets: List[Dict[str, Any]] = []
        for t in targets:
            typ = t.get("type")
            url = t.get("url") or ""
            if typ == "page" and url.startswith(self.origin):
                page_target = t
            if typ == "service_worker" and url.startswith(self.origin):
                sw_targets.append(t)

        if not page_target:
            print(f"No page target for origin {self.origin} found. Some collectors may not function.", file=sys.stderr)

        page_session: Optional[str] = None
        if page_target:
            page_session = await self.client.attach(page_target["targetId"])

        # Enable domains on page session
        if page_session:
            await self.safe_enable(page_session, "Storage.enable")
            await self.safe_enable(page_session, "DOMStorage.enable")
            await self.safe_enable(page_session, "IndexedDB.enable")
            await self.safe_enable(page_session, "Network.enable")
            await self.safe_enable(page_session, "Debugger.enable")  # for wasm in page

        # Collect in passes if requested
        passes = 2 if self.two_pass else 1
        pass_hashes: List[Dict[str, str]] = []

        for p in range(passes):
            pass_id = f"pass_{p+1}"
            print(f"Starting acquisition {pass_id}...", file=sys.stderr)

            if "service_workers" in self.collect_set:
                await self.collect_service_workers(sw_targets)

            if "cache" in self.collect_set and page_session:
                await self.collect_cache_storage(page_session)

            if "indexeddb" in self.collect_set and page_session:
                await self.collect_indexeddb(page_session)

            if "localstorage" in self.collect_set and page_session:
                await self.collect_localstorage(page_session)

            if "wasm" in self.collect_set:
                await self.collect_wasm(page_session, sw_targets)

            if "webrtc" in self.collect_set and page_session:
                await self.collect_webrtc(page_session)

            # Compute hashes snapshot for consistency check
            digests = {}
            for art in self.artifacts:
                if "path" in art and os.path.isfile(art["path"]):
                    with open(art["path"], "rb") as f:
                        digests[os.path.relpath(art["path"], self.outpath)] = sha256_hex(f.read())
            pass_hashes.append(digests)

        consistency = {}
        if passes == 2:
            a, b = pass_hashes
            changed = {k: (a.get(k), b.get(k)) for k in set(a.keys()).union(set(b.keys())) if a.get(k) != b.get(k)}
            consistency = {
                "pass1_count": len(a),
                "pass2_count": len(b),
                "differences_count": len(changed),
                "differences": changed,
            }

        # Build manifest
        manifest = {
            "tool": "WebWorkspace Forensic Collector: Browser Runtime Artifact Sealer",
            "category": "forensics",
            "version": "1.0.0",
            "case_id": self.case_id,
            "operator": self.operator,
            "origin": self.origin,
            "ws_url": self.ws_url,
            "start_time": self.start_time,
            "end_time": now_rfc3339(),
            "chain_id": self.chain_id,
            "pii_minimization": not self.redactor.authorized_secrets,
            "throttle_ms": self.throttle_ms,
            "max_bytes": self.max_bytes,
            "artifacts": self.artifacts,
            "consistency": consistency,
            "playbook": self.playbook,
            "ethics": ETHICAL_WARNING,
        }

        # Write manifest and signature
        manifest_path = os.path.join(self.outpath, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
        manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = self.sealer.sign(manifest_bytes)
        signature = {
            "algorithm": "HMAC-SHA256",
            "signature": sig,
            "public": self.sealer.export_public(),
            "timestamp": now_rfc3339(),
        }
        with open(os.path.join(self.outpath, "manifest.signature.json"), "w", encoding="utf-8") as f:
            json.dump(signature, f, indent=2, sort_keys=True)

        # Zip bundle
        bundle_path = os.path.join(self.outpath, "bundle.zip")
        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(self.outpath):
                for name in files:
                    p = os.path.join(root, name)
                    if os.path.abspath(p) == os.path.abspath(bundle_path):
                        continue
                    arcname = os.path.relpath(p, self.outpath)
                    z.write(p, arcname)

        print(f"Acquisition complete. Bundle at {bundle_path}", file=sys.stderr)
        await self.client.close()

    async def safe_enable(self, session: str, method: str):
        try:
            await self.client.send(method, {}, session)
        except Exception as e:
            print(f"Enable {method} failed: {e}", file=sys.stderr)

    async def collect_service_workers(self, sw_targets: List[Dict[str, Any]]):
        # Attach to SW targets and capture scripts via Debugger
        for t in sw_targets:
            try:
                sid = await self.client.attach(t["targetId"])
                await self.safe_enable(sid, "Debugger.enable")
                scripts: Dict[str, Dict[str, Any]] = {}

                def on_parsed(evt):
                    if evt.get("sessionId") != sid:
                        return
                    params = evt.get("params", {})
                    scriptId = params.get("scriptId")
                    url = params.get("url") or ""
                    if not scriptId:
                        return
                    scripts[scriptId] = {"url": url}

                self.client.on("Debugger.scriptParsed", on_parsed, sessionId=sid)
                # Give a moment to receive existing scripts
                await asyncio.sleep(0.5)

                for scriptId, meta in scripts.items():
                    try:
                        # Attempt to fetch source (JS)
                        source = await self.client.send("Debugger.getScriptSource", {"scriptId": scriptId}, sid)
                        text = source.get("scriptSource", "")
                        data = text.encode("utf-8")
                        fname = f"service_workers/{t['targetId']}/{os.path.basename(meta['url']) or scriptId}.js"
                        fpath = os.path.join(self.outpath, fname)
                        ensure_dir(os.path.dirname(fpath))
                        with open(fpath, "wb") as f:
                            f.write(data[: self.max_bytes])
                        self.artifacts.append({
                            "type": "service_worker_script",
                            "targetId": t["targetId"],
                            "url": meta["url"],
                            "path": fpath,
                            "sha256": sha256_hex(data[: self.max_bytes]),
                            "truncated": len(data) > self.max_bytes,
                        })
                    except CDPError:
                        # Might be WASM; try bytecode
                        try:
                            bc = await self.client.send("Debugger.getWasmBytecode", {"scriptId": scriptId}, sid)
                            b = base64.b64decode(bc.get("bytecode", ""))
                            fname = f"service_workers/{t['targetId']}/{os.path.basename(meta['url']) or scriptId}.wasm"
                            fpath = os.path.join(self.outpath, fname)
                            ensure_dir(os.path.dirname(fpath))
                            with open(fpath, "wb") as f:
                                f.write(b[: self.max_bytes])
                            self.artifacts.append({
                                "type": "service_worker_wasm",
                                "targetId": t["targetId"],
                                "url": meta["url"],
                                "path": fpath,
                                "sha256": sha256_hex(b[: self.max_bytes]),
                                "truncated": len(b) > self.max_bytes,
                            })
                        except Exception as e:
                            print(f"SW script fetch failed: {e}", file=sys.stderr)
                await self.client.detach(sid)
            except Exception as e:
                print(f"Service worker attach failed: {e}", file=sys.stderr)

    async def collect_cache_storage(self, session: str):
        try:
            caches = await self.client.send("CacheStorage.requestCacheNames", {"securityOrigin": self.origin}, session)
        except Exception as e:
            print(f"CacheStorage not available: {e}", file=sys.stderr)
            return
        for cache in caches.get("caches", []):
            cacheId = cache.get("cacheId")
            cache_dir = os.path.join(self.outpath, "cache", cache.get("cacheName", "unnamed"))
            ensure_dir(cache_dir)
            total = 0
            while True:
                params = {"cacheId": cacheId, "skipCount": total, "pageSize": 100}
                try:
                    entries = await self.client.send("CacheStorage.requestEntries", params, session)
                except Exception as e:
                    print(f"CacheStorage.requestEntries failed: {e}", file=sys.stderr)
                    break
                ents = entries.get("cacheDataEntries", [])
                if not ents:
                    break
                for e in ents:
                    req = e.get("request", {}) or {}
                    url = req.get("url", "")
                    # Fetch body
                    try:
                        resp = await self.client.send("CacheStorage.requestCachedResponse", {
                            "cacheId": cacheId,
                            "requestURL": url,
                            "requestHeaders": req.get("headers", []),
                        }, session)
                        info = resp.get("response", {}) or {}
                        body_b64 = info.get("body", "")
                        body = base64.b64decode(body_b64) if body_b64 else b""
                        # Save metadata and body truncated
                        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", url)[:200]
                        body_path = os.path.join(cache_dir, f"{safe_name}.body")
                        meta_path = os.path.join(cache_dir, f"{safe_name}.json")
                        with open(body_path, "wb") as f:
                            f.write(body[: self.max_bytes])
                        meta = {
                            "type": "cache_entry",
                            "url": url,
                            "request": req,
                            "response": {k: v for k, v in info.items() if k != "body"},
                            "body_path": body_path,
                            "sha256": sha256_hex(body[: self.max_bytes]),
                            "truncated": len(body) > self.max_bytes,
                        }
                        with open(meta_path, "w", encoding="utf-8") as f:
                            json.dump(self.redactor.redact_obj(meta), f, indent=2, sort_keys=True)
                        self.artifacts.append({
                            "type": "cache_entry",
                            "url": url,
                            "path": body_path,
                            "sha256": sha256_hex(body[: self.max_bytes]),
                            "truncated": len(body) > self.max_bytes,
                        })
                    except Exception as ex:
                        print(f"Fetch cached response failed for {url}: {ex}", file=sys.stderr)
                total += len(ents)

    async def collect_indexeddb(self, session: str):
        try:
            dbs = await self.client.send("IndexedDB.requestDatabaseNames", {"securityOrigin": self.origin}, session)
        except Exception as e:
            print(f"IndexedDB not available: {e}", file=sys.stderr)
            return
        for dbname in dbs.get("databaseNames", []):
            try:
                dbinfo = await self.client.send("IndexedDB.requestDatabase", {
                    "securityOrigin": self.origin,
                    "databaseName": dbname
                }, session)
            except Exception as e:
                print(f"IndexedDB.requestDatabase failed: {e}", file=sys.stderr)
                continue
            db_dir = os.path.join(self.outpath, "indexeddb", re.sub(r"[^A-Za-z0-9_.-]+", "_", dbname))
            ensure_dir(db_dir)
            schema_path = os.path.join(db_dir, "schema.json")
            with open(schema_path, "w", encoding="utf-8") as f:
                json.dump(self.redactor.redact_obj(dbinfo), f, indent=2, sort_keys=True)
            self.artifacts.append({
                "type": "indexeddb_schema",
                "database": dbname,
                "path": schema_path,
                "sha256": sha256_hex(json.dumps(self.redactor.redact_obj(dbinfo), sort_keys=True).encode("utf-8")),
            })
            # Dump each object store
            for os_info in dbinfo.get("objectStores", []):
                store_name = os_info.get("name", "store")
                skip = 0
                pageSize = 200
                records_path = os.path.join(db_dir, f"{re.sub(r'[^A-Za-z0-9_.-]+','_', store_name)}.jsonl")
                with open(records_path, "w", encoding="utf-8") as outf:
                    while True:
                        try:
                            data = await self.client.send("IndexedDB.requestData", {
                                "securityOrigin": self.origin,
                                "databaseName": dbname,
                                "objectStoreName": store_name,
                                "indexName": "",
                                "skipCount": skip,
                                "pageSize": pageSize,
                            }, session)
                        except Exception as e:
                            print(f"IndexedDB.requestData failed: {e}", file=sys.stderr)
                            break
                        entries = data.get("objectStoreDataEntries", [])
                        if not entries:
                            break
                        for entry in entries:
                            redact_entry = self.redactor.redact_obj(entry)
                            outf.write(json.dumps(redact_entry, sort_keys=True) + "\n")
                        skip += len(entries)
                self.artifacts.append({
                    "type": "indexeddb_records",
                    "database": dbname,
                    "store": store_name,
                    "path": records_path,
                    "sha256": sha256_hex(open(records_path, "rb").read()),
                })

    async def collect_localstorage(self, session: str):
        storage_id = {"securityOrigin": self.origin, "isLocalStorage": True}
        try:
            res = await self.client.send("DOMStorage.getDOMStorageItems", {"storageId": storage_id}, session)
        except Exception as e:
            print(f"LocalStorage not available: {e}", file=sys.stderr)
            return
        items = res.get("entries", [])
        ls: Dict[str, str] = {}
        for ent in items:
            if isinstance(ent, (list, tuple)):
                if len(ent) >= 2:
                    k, v = ent[0], ent[1]
                    ls[str(k)] = str(v)
            elif isinstance(ent, dict) and "key" in ent and "value" in ent:
                ls[str(ent.get("key"))] = str(ent.get("value"))
        ls_redacted = self.redactor.redact_obj(ls)
        path = os.path.join(self.outpath, "localstorage.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(ls_redacted, f, indent=2, sort_keys=True)
        self.artifacts.append({
            "type": "localstorage",
            "path": path,
            "sha256": sha256_hex(json.dumps(ls_redacted, sort_keys=True).encode("utf-8")),
        })

    async def collect_wasm(self, page_session: Optional[str], sw_targets: List[Dict[str, Any]]):
        # From page
        if page_session:
            scripts: Dict[str, Dict[str, Any]] = {}

            def on_parsed(evt):
                if evt.get("sessionId") != page_session:
                    return
                params = evt.get("params", {})
                scriptId = params.get("scriptId")
                url = (params.get("url") or "")
                if not scriptId:
                    return
                # Heuristic: wasm when url ends with .wasm or param 'hash' indicates wasm
                if url.endswith(".wasm") or str(params.get("hash", "")).startswith("wasm"):
                    scripts[scriptId] = {"url": url}

            self.client.on("Debugger.scriptParsed", on_parsed, sessionId=page_session)
            await asyncio.sleep(0.5)
            for sid, meta in scripts.items():
                try:
                    bc = await self.client.send("Debugger.getWasmBytecode", {"scriptId": sid}, page_session)
                    b = base64.b64decode(bc.get("bytecode", ""))
                    fname = f"wasm/page/{os.path.basename(meta['url']) or sid}.wasm"
                    fpath = os.path.join(self.outpath, fname)
                    ensure_dir(os.path.dirname(fpath))
                    with open(fpath, "wb") as f:
                        f.write(b[: self.max_bytes])
                    self.artifacts.append({
                        "type": "wasm_module",
                        "context": "page",
                        "url": meta["url"],
                        "path": fpath,
                        "sha256": sha256_hex(b[: self.max_bytes]),
                        "truncated": len(b) > self.max_bytes,
                    })
                except Exception:
                    pass

        # From service workers are handled in collect_service_workers

    async def collect_webrtc(self, session: str):
        webrtc_supported = True
        try:
            await self.client.send("WebRTC.enable", {}, session)
        except Exception:
            webrtc_supported = False
        events: List[Dict[str, Any]] = []
        start = time.time()

        if webrtc_supported:
            def on_pc(evt):
                if evt.get("sessionId") == session:
                    events.append(evt)
            def on_ice(evt):
                if evt.get("sessionId") == session:
                    events.append(evt)
            self.client.on("WebRTC.peerConnectionUpdated", on_pc, sessionId=session)
            self.client.on("WebRTC.iceCandidateAdded", on_ice, sessionId=session)
        else:
            # Fallback: Log domain; capture 'webrtc' logs where SDP may appear
            try:
                await self.client.send("Log.enable", {}, session)
                def on_log(evt):
                    if evt.get("sessionId") != session:
                        return
                    params = evt.get("params", {})
                    ent = params.get("entry", {})
                    if ent.get("source") == "webrtc":
                        events.append(evt)
                self.client.on("Log.entryAdded", on_log, sessionId=session)
            except Exception:
                pass

        # Also collect limited WebSocket signaling hints without payload storage
        ws_events: List[Dict[str, Any]] = []
        try:
            def ws_created(evt):
                if evt.get("sessionId") != session:
                    return
                params = evt.get("params", {})
                ws_events.append({"type": "WebSocketCreated", "url": params.get("url", ""), "timestamp": params.get("timestamp")})
            def ws_frame_sent(evt):
                if evt.get("sessionId") != session:
                    return
                params = evt.get("params", {})
                # redact frame payload but keep size and SDP hint
                payload_data = (params.get("response", {}) or {}).get("payloadData", "")
                sdp_hint = bool(re.search(r"(?m)^(v=0|a=candidate:)", payload_data or ""))
                ws_events.append({
                    "type": "WebSocketFrameSent",
                    "opcode": (params.get("response", {}) or {}).get("opcode"),
                    "length": len(payload_data) if isinstance(payload_data, str) else 0,
                    "sdp_hint": sdp_hint,
                    "timestamp": params.get("timestamp"),
                })
            def ws_frame_recv(evt):
                if evt.get("sessionId") != session:
                    return
                params = evt.get("params", {})
                payload_data = (params.get("response", {}) or {}).get("payloadData", "")
                sdp_hint = bool(re.search(r"(?m)^(v=0|a=candidate:)", payload_data or ""))
                ws_events.append({
                    "type": "WebSocketFrameReceived",
                    "opcode": (params.get("response", {}) or {}).get("opcode"),
                    "length": len(payload_data) if isinstance(payload_data, str) else 0,
                    "sdp_hint": sdp_hint,
                    "timestamp": params.get("timestamp"),
                })
            self.client.on("Network.webSocketCreated", ws_created, sessionId=session)
            self.client.on("Network.webSocketFrameSent", ws_frame_sent, sessionId=session)
            self.client.on("Network.webSocketFrameReceived", ws_frame_recv, sessionId=session)
        except Exception:
            pass

        # Collect for a window without capturing media
        await asyncio.sleep(self.webrtc_window_sec)

        path = os.path.join(self.outpath, "webrtc_events.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "start": start,
                "end": time.time(),
                "events": self.redactor.redact_obj(events),
                "network_ws_meta": ws_events,
                "note": "Contains WebRTC signaling/ICE related events where supported; payloads redacted/minimized.",
            }, f, indent=2, sort_keys=True)
        self.artifacts.append({
            "type": "webrtc_signaling",
            "path": path,
            "sha256": sha256_hex(open(path, "rb").read()),
        })

def parse_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="WebWorkspace Forensic Collector: Browser Runtime Artifact Sealer")
    ap.add_argument("--ws-endpoint", required=True, help="CDP WebSocket endpoint, e.g., ws://127.0.0.1:9222/devtools/browser/<id> or page target")
    ap.add_argument("--origin", required=True, help="Target security origin, e.g., https://example.com")
    ap.add_argument("--out", required=True, help="Output directory for bundle and artifacts")
    ap.add_argument("--operator", required=True, help="Operator name/ID for chain-of-custody")
    ap.add_argument("--case-id", required=True, help="Case identifier")
    ap.add_argument("--redact-key-pattern", action="append", default=[], help="Regex for keys to redact (can be repeated)")
    ap.add_argument("--authorize-secrets", action="store_true", help="Allow capturing secrets (cookies/tokens) without redaction")
    ap.add_argument("--max-bytes", type=int, default=5_000_000, help="Max bytes per resource body to store")
    ap.add_argument("--throttle-ms", type=int, default=25, help="Throttle between CDP calls (ms)")
    ap.add_argument("--webrtc-window-sec", type=int, default=10, help="Window to record WebRTC signaling (seconds)")
    ap.add_argument("--collect", nargs="*", default=["service_workers", "cache", "indexeddb", "localstorage", "wasm", "webrtc"],
                    help="Collectors to run: service_workers cache indexeddb localstorage wasm webrtc")
    ap.add_argument("--two-pass", action="store_true", help="Run two passes and record hash consistency")
    return ap.parse_args(argv)

def main():
    args = parse_args(sys.argv[1:])
    collector = WebWorkspaceCollector(
        ws_url=args.ws_endpoint,
        origin=args.origin,
        outpath=args.out,
        operator=args.operator,
        case_id=args.case_id,
        redact_patterns=args.redact_key_pattern,
        authorized_secrets=args.authorize_secrets,
        max_bytes=args.max_bytes,
        throttle_ms=args.throttle_ms,
        webrtc_window_sec=args.webrtc_window_sec,
        collect=args.collect,
        two_pass=args.two_pass,
    )
    asyncio.run(collector.run())

if __name__ == "__main__":
    main()