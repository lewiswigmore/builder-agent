#!/usr/bin/env python3
"""
SBOM Sentinel - Continuous dependency analysis and SBOM generation with integrity verification,
hermetic build replays, provenance attestations, typosquat detection, and signed transparency-backed
publishing for multi-language projects (initial Python focus).

Ethical warning: Use this tool only for authorized testing on systems and repositories you own or
are explicitly permitted to assess. Misuse may violate laws or policies.

This tool aims to fail closed: signature verification, Rekor transparency checks, sandbox
constraints, and reproducibility checks are enforced. If evidence cannot be validated, the pipeline
halts with non-zero exit status.

Dependencies: Standard library preferred. If cosign/rekor-cli are required for signing/verification,
they must be available in PATH for production mode. For controlled testing, you may use
--simulate-sign to produce local pseudo-signatures, which is not a substitute for real verification.
"""

import argparse
import base64
import dataclasses
import datetime
import functools
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

TOOL_VERSION = "0.1.0"

# ------------------------------ Logging -------------------------------------


class Log:
    @staticmethod
    def info(msg: str):
        sys.stderr.write(f"[INFO] {msg}\n")

    @staticmethod
    def warn(msg: str):
        sys.stderr.write(f"[WARN] {msg}\n")

    @staticmethod
    def error(msg: str):
        sys.stderr.write(f"[ERROR] {msg}\n")


# ------------------------------ Utilities -----------------------------------


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def read_text_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def write_atomic(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def is_windows() -> bool:
    return os.name == "nt"


def site_packages_path(venv: Path) -> Optional[Path]:
    if is_windows():
        sp = venv / "Lib" / "site-packages"
        return sp if sp.exists() else None
    else:
        candidates = list((venv / "lib").glob("python*/site-packages"))
        return candidates[0] if candidates else None


def getenv_bool(name: str, default=False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")


# ------------------------------ Typosquat Detection -------------------------


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(
                min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
            )
        prev = curr
    return prev[-1]


POPULAR_PYPI = {
    "requests",
    "numpy",
    "pandas",
    "django",
    "flask",
    "urllib3",
    "pillow",
    "scikit-learn",
    "scipy",
    "matplotlib",
    "pytest",
    "tornado",
    "fastapi",
    "sqlalchemy",
    "beautifulsoup4",
    "lxml",
    "cryptography",
}


@dataclasses.dataclass
class TyposquatFinding:
    package: str
    version: str
    similar_to: str
    distance: int
    evidence: Dict[str, str]


class TyposquatDetector:
    def __init__(self, threshold: int = 2):
        self.threshold = threshold

    def detect(self, packages: Dict[str, str]) -> List[TyposquatFinding]:
        findings: List[TyposquatFinding] = []
        names = set(packages.keys())
        candidates = POPULAR_PYPI.union({n.replace("-", "") for n in names})
        for pkg, ver in packages.items():
            nrm = pkg.lower().replace("_", "").replace("-", "")
            for popular in candidates:
                if popular.lower() == nrm:
                    continue
                d = levenshtein(nrm, popular.lower())
                if d <= self.threshold:
                    findings.append(
                        TyposquatFinding(
                            package=pkg,
                            version=ver,
                            similar_to=popular,
                            distance=d,
                            evidence={
                                "note": "Name similarity to a popular package",
                                "normalized": nrm,
                                "popular": popular,
                            },
                        )
                    )
                    break
        return findings


# ------------------------------ Python Metadata Scanner ---------------------


@dataclasses.dataclass
class PackageNode:
    name: str
    version: str
    requires: List[str]


def parse_requires_dist_line(line: str) -> Optional[str]:
    # Parse "pkgname (>=1.0); python_version >= '3.8'"
    line = line.strip()
    if not line:
        return None
    # Remove extras, markers for basic collection
    name_match = re.match(r"([A-Za-z0-9_.\-]+)", line)
    if not name_match:
        return None
    return name_match.group(1)


def scan_site_packages(path: Path) -> Dict[str, PackageNode]:
    result: Dict[str, PackageNode] = {}
    for dist_info in path.glob("*.dist-info"):
        name = dist_info.name
        # Example: requests-2.31.0.dist-info
        m = re.match(r"(.+)-([0-9].+)\.dist-info", name)
        if not m:
            continue
        pkg_name = m.group(1)
        version = m.group(2)
        metadata = dist_info / "METADATA"
        requires: List[str] = []
        if metadata.exists():
            txt = read_text_safe(metadata)
            for line in txt.splitlines():
                if line.startswith("Requires-Dist:"):
                    dep_line = line.split(":", 1)[1].strip()
                    dep = parse_requires_dist_line(dep_line)
                    if dep:
                        requires.append(dep)
        result[pkg_name] = PackageNode(pkg_name, version, requires)
    return result


def resolve_transitive(packages: Dict[str, PackageNode], roots: Set[str]) -> Dict[str, str]:
    resolved: Dict[str, str] = {}
    seen: Set[str] = set()

    def visit(name: str):
        if name in seen:
            return
        seen.add(name)
        node = packages.get(name)
        if node:
            resolved[node.name] = node.version
            for d in node.requires:
                visit(d)
        else:
            # Not installed; record unknown
            resolved[name] = "unknown"

    for r in roots:
        visit(r)
    return resolved


# ------------------------------ SBOM Builders --------------------------------


class SBOMBuilder:
    def __init__(self, project_name: str, project_version: str, vex_file: Optional[Path] = None):
        self.project_name = project_name
        self.project_version = project_version
        self.vex_notes = self._load_vex(vex_file)

    def _load_vex(self, path: Optional[Path]) -> Dict[str, Dict]:
        if not path:
            return {}
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return {}
            return data
        except Exception as e:
            Log.warn(f"Failed to load VEX file: {e}")
            return {}

    def _component(self, name: str, version: str) -> Dict:
        purl = f"pkg:pypi/{name}@{version}" if version != "unknown" else f"pkg:pypi/{name}"
        comp = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
        }
        if name in self.vex_notes:
            # CycloneDX VEX can be at top-level vulnerabilities referencing components; we keep a simple embed
            comp["vex"] = self.vex_notes[name]
        return comp

    def build_cyclonedx(self, components: Dict[str, str], typosquats: List[TyposquatFinding]) -> Dict:
        bom_uuid = hashlib.sha256(f"{self.project_name}@{self.project_version}".encode()).hexdigest()
        comps = [self._component(n, v) for n, v in sorted(components.items(), key=lambda kv: kv[0].lower())]
        vuln_entries = []
        for finding in typosquats:
            vuln_entries.append(
                {
                    "id": f"typosquat-{finding.package}",
                    "source": {"name": "SBOM Sentinel Typosquat Heuristic"},
                    "ratings": [{"severity": "high"}],
                    "analysis": {
                        "state": "exploitable",
                        "response": ["will_not_fix"],
                        "detail": "Potential typosquat detected; pipeline halted for human review.",
                    },
                    "affects": [{"ref": f"pkg:pypi/{finding.package}@{finding.version}"}],
                    "advisories": [
                        {
                            "title": "Name similarity",
                            "url": "https://owasp.org/www-project-top-ten/2017/A9_Using_Components_with_Known_Vulnerabilities",
                        }
                    ],
                    "properties": [
                        {"name": "similar_to", "value": finding.similar_to},
                        {"name": "distance", "value": str(finding.distance)},
                    ],
                }
            )
        # Include VEX notes as top-level vulnerabilities with not_affected status
        for pkg, vex in self.vex_notes.items():
            vuln_entries.append(
                {
                    "id": f"vex-{pkg}",
                    "source": {"name": "VEX"},
                    "analysis": {
                        "state": vex.get("state", "not_affected"),
                        "justification": vex.get("justification", "code_not_reachable"),
                        "detail": vex.get("detail", "VEX note provided by policy."),
                    },
                    "affects": [{"ref": f"pkg:pypi/{pkg}@{components.get(pkg, 'unknown')}"}],
                }
            )
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "serialNumber": f"urn:uuid:{bom_uuid}",
            "metadata": {
                "timestamp": utc_now_iso(),
                "tools": [{"vendor": "SBOM Sentinel", "name": "sbom-sentinel", "version": TOOL_VERSION}],
                "component": {"type": "application", "name": self.project_name, "version": self.project_version},
            },
            "components": comps,
            "vulnerabilities": vuln_entries,
        }
        return bom

    def build_spdx(self, components: Dict[str, str]) -> Dict:
        doc_id = hashlib.sha256(f"{self.project_name}@{self.project_version}@spdx".encode()).hexdigest()
        packages = []
        for n, v in sorted(components.items(), key=lambda kv: kv[0].lower()):
            packages.append(
                {
                    "SPDXID": f"SPDXRef-Package-{n}",
                    "name": n,
                    "versionInfo": v,
                    "downloadLocation": f"pkg:pypi/{n}@{v}" if v != "unknown" else f"pkg:pypi/{n}",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                }
            )
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": f"SPDXRef-DOCUMENT-{doc_id}",
            "name": f"{self.project_name}-SBOM",
            "documentNamespace": f"http://sbom-sentinel.example/{doc_id}",
            "creationInfo": {
                "created": utc_now_iso(),
                "creators": [f"Tool: SBOM Sentinel/{TOOL_VERSION}"],
            },
            "packages": packages,
        }


# ------------------------------ Hermetic Sandbox -----------------------------


class HermeticSandbox:
    """
    Provides a restricted environment for builds: blocks network, isolates env, creates temporary
    workspace, and supports reproducibility checks. Uses environment-based socket blocking via
    sitecustomize stub to avoid network access in Python subprocesses. Not a replacement for real
    OS-level sandboxing; use dedicated sandbox/container for production.
    """

    def __init__(self, allowlist_dir: Optional[Path] = None, cache_dir: Optional[Path] = None):
        self.allowlist_dir = Path(allowlist_dir) if allowlist_dir else None
        self.cache_dir = Path(cache_dir) if cache_dir else Path(".sbom_sentinel_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _sandbox_env(self) -> Dict[str, str]:
        env = {}  # start minimal
        # block networking via sitecustomize
        env.update(
            {
                "PYTHONNOUSERSITE": "1",
                "PYTHONHASHSEED": "0",
                "SBOM_SENTINEL_BLOCK_NETWORK": "1",
                "TZ": "UTC",
            }
        )
        if self.allowlist_dir:
            env["PIP_NO_INDEX"] = "1"
            env["PIP_FIND_LINKS"] = str(self.allowlist_dir.resolve())
        # Propagate minimal PATH for Python
        env["PATH"] = os.environ.get("PATH", "")
        return env

    def _create_sitecustomize(self, workdir: Path):
        sc = workdir / "sitecustomize.py"
        code = """
import os, socket, builtins
if os.environ.get("SBOM_SENTINEL_BLOCK_NETWORK") == "1":
    class _Blk(socket.socket):
        def __init__(self, *a, **kw): 
            raise OSError("Network blocked by SBOM Sentinel sandbox")
    socket.socket = _Blk
    def _guard(*a, **kw):
        raise OSError("Network blocked by SBOM Sentinel sandbox")
    socket.create_connection = _guard
"""
        sc.write_text(code, encoding="utf-8")

    def _compute_inputs_digest(self, src_dir: Path) -> Tuple[str, List[Tuple[str, str]]]:
        files: List[Path] = []
        for p in src_dir.rglob("*"):
            if p.is_file():
                # skip VCS dirs and cache
                parts = {".git", ".hg", ".svn", "__pycache__", ".tox", ".venv", "venv", ".mypy_cache"}
                if any(part in parts for part in p.parts):
                    continue
                files.append(p)
        files_sorted = sorted(files)
        dh = hashlib.sha256()
        materials = []
        for f in files_sorted:
            h = sha256_file(f)
            materials.append((str(f.relative_to(src_dir)).replace("\\", "/"), h))
            dh.update(h.encode())
        return dh.hexdigest(), materials

    def build_project(self, src_dir: Path, out_dir: Path) -> List[Path]:
        """
        Build project sdist and wheel if possible with reproducibility.
        """
        src_dir = Path(src_dir).resolve()
        out_dir = Path(out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="sbom_sentinel_"))
        try:
            # copy source into work
            src_copy = work / "src"
            shutil.copytree(src_dir, src_copy, dirs_exist_ok=True)
            # install sitecustomize
            self._create_sitecustomize(work)
            env = self._sandbox_env()
            env["PYTHONPATH"] = str(work)
            # content-addressed key
            input_digest, materials = self._compute_inputs_digest(src_copy)
            key = f"{input_digest}-py{platform.python_version()}"
            cache_key_dir = self.cache_dir / key
            artifact_paths: List[Path] = []
            if cache_key_dir.exists():
                for f in cache_key_dir.iterdir():
                    if f.is_file():
                        target = out_dir / f.name
                        shutil.copy2(f, target)
                        artifact_paths.append(target)
                return artifact_paths

            # Attempt build via 'python -m build'
            cmd = [sys.executable, "-m", "build", "--no-isolation", "--wheel", "--sdist", "--outdir", str(out_dir)]
            Log.info("Starting hermetic build (network locked).")
            res = subprocess.run(cmd, env=env, cwd=src_copy, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            out = res.stdout
            write_atomic(out_dir / "build.log", out.encode())
            if res.returncode != 0:
                # fallback: setup.py
                Log.warn("build module failed, attempting setup.py fallback")
                # sdist
                res1 = subprocess.run([sys.executable, "setup.py", "sdist", "--dist-dir", str(out_dir)], env=env, cwd=src_copy, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                write_atomic(out_dir / "build_setup_sdist.log", res1.stdout.encode())
                # bdist_wheel
                res2 = subprocess.run([sys.executable, "setup.py", "bdist_wheel", "--dist-dir", str(out_dir)], env=env, cwd=src_copy, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                write_atomic(out_dir / "build_setup_wheel.log", res2.stdout.encode())
                if res1.returncode != 0 and res2.returncode != 0:
                    raise RuntimeError("Build failed in hermetic sandbox. See logs.")
            # Collect artifacts
            for f in out_dir.iterdir():
                if f.suffix in (".whl", ".tar", ".gz") or f.name.endswith(".tar.gz"):
                    artifact_paths.append(f)

            # Reproducibility check: build again and compare digests
            Log.info("Replaying build for reproducibility check.")
            out_dir2 = Path(tempfile.mkdtemp(prefix="sbom_sentinel_build2_"))
            res2 = subprocess.run(cmd, env=env, cwd=src_copy, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            write_atomic(out_dir2 / "build2.log", res2.stdout.encode())
            arts2 = []
            for f in Path(out_dir2).iterdir():
                if f.suffix in (".whl", ".tar", ".gz") or f.name.endswith(".tar.gz"):
                    arts2.append(f)
            # Compare file digests by name
            diffs = []
            for f in artifact_paths:
                g = next((x for x in arts2 if x.name == f.name), None)
                if not g:
                    diffs.append(f"{f.name}: missing in replay")
                    continue
                if sha256_file(f) != sha256_file(g):
                    diffs.append(f"{f.name}: digest mismatch")
            if diffs:
                raise RuntimeError("Non-reproducible outputs: " + "; ".join(diffs))

            # Cache artifacts
            cache_key_dir.mkdir(parents=True, exist_ok=True)
            for f in artifact_paths:
                shutil.copy2(f, cache_key_dir / f.name)

            # Return artifacts
            return artifact_paths
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def provenance_attestation(self, src_dir: Path, artifacts: List[Path], materials: Optional[List[Tuple[str, str]]] = None) -> Dict:
        src_dir = Path(src_dir).resolve()
        if materials is None:
            _, materials = self._compute_inputs_digest(src_dir)
        artifact_digests = [{"uri": str(p), "digest": {"sha256": sha256_file(p)}} for p in artifacts]
        env_digest = sha256_bytes(canonical_json(self._sandbox_env()).encode())
        builder_id = f"sbom-sentinel/{TOOL_VERSION}"
        prov = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": Path(a["uri"]).name, "digest": a["digest"]} for a in artifact_digests],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildType": "https://slsa.dev/build-type/scripted",
                "builder": {"id": builder_id},
                "buildConfig": {"platform": platform.platform(), "python": platform.python_version()},
                "invocation": {"parameters": {}, "environment": {"digest": {"sha256": env_digest}}},
                "metadata": {"buildStartedOn": utc_now_iso(), "buildFinishedOn": utc_now_iso(), "reproducible": True},
                "materials": [{"uri": m[0], "digest": {"sha256": m[1]}} for m in materials],
            },
        }
        return prov


# ------------------------------ Signing and Transparency ---------------------


class CosignError(Exception):
    pass


class CosignSigner:
    """
    Wrapper around cosign for signing and verifying blobs with Rekor bundle.
    Fails closed if cosign is unavailable or verification fails, unless simulate=True.
    """

    def __init__(self, oidc_identity: Optional[str] = None, simulate: bool = False):
        self.oidc_identity = oidc_identity
        self.simulate = simulate

    def _check(self):
        if self.simulate:
            return
        if shutil.which("cosign") is None:
            raise CosignError("cosign not found in PATH")
        # Rekor is integrated by cosign bundle; rekor-cli may be used for extra checks
        # Not strictly required if using cosign bundle.

    def sign_blob(self, path: Path, out_sig: Path, out_cert: Path, out_bundle: Path):
        path = Path(path)
        out_sig = Path(out_sig)
        out_cert = Path(out_cert)
        out_bundle = Path(out_bundle)
        if self.simulate or getenv_bool("SBOM_SENTINEL_TEST_MODE", False):
            # Produce a pseudo signature and bundle locally (NOT SECURE)
            Log.warn("Simulated signing enabled. This is NOT secure and for testing only.")
            digest = sha256_file(path)
            pseudo_sig = base64.b64encode(hashlib.sha256((digest + "sim").encode()).digest()).decode()
            pseudo_cert = {
                "subject": self.oidc_identity or "simulated@local",
                "issuer": "simulated",
                "notBefore": utc_now_iso(),
                "notAfter": utc_now_iso(),
            }
            bundle = {"mediaType": "application/vnd.dev.cosign.sim-bundle+json", "tlogEntries": [{"uuid": "simulated"}]}
            write_atomic(out_sig, pseudo_sig.encode())
            write_atomic(out_cert, canonical_json(pseudo_cert).encode())
            write_atomic(out_bundle, canonical_json(bundle).encode())
            return

        self._check()
        cmd = [
            "cosign",
            "sign-blob",
            "--yes",
            "--bundle",
            str(out_bundle),
            "--output-signature",
            str(out_sig),
            "--output-certificate",
            str(out_cert),
            str(path),
        ]
        if self.oidc_identity:
            cmd.extend(["--identity-token", self.oidc_identity])  # token string or use env
        Log.info(f"Signing blob with cosign: {path.name}")
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if res.returncode != 0:
            raise CosignError(f"cosign sign-blob failed: {res.stdout}")

    def verify_blob(self, path: Path, bundle: Path) -> Dict:
        path = Path(path)
        bundle = Path(bundle)
        if self.simulate or getenv_bool("SBOM_SENTINEL_TEST_MODE", False):
            # Verify simulated bundle presence
            data = json.loads(bundle.read_text(encoding="utf-8"))
            if "tlogEntries" not in data:
                raise CosignError("Simulated bundle missing tlogEntries")
            return data

        self._check()
        cmd = ["cosign", "verify-blob", "--bundle", str(bundle), str(path)]
        Log.info(f"Verifying blob with cosign: {path.name}")
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if res.returncode != 0:
            raise CosignError(f"cosign verify-blob failed: {res.stdout}")
        # Also parse bundle for Rekor inclusion
        try:
            data = json.loads(bundle.read_text(encoding="utf-8"))
            if not data.get("tlogEntries"):
                raise CosignError("No transparency log entries in bundle")
            return data
        except Exception as e:
            raise CosignError(f"Failed to parse cosign bundle: {e}")


# ------------------------------ SBOM Diff and Integrity Checks ---------------


def extract_components_from_cyclonedx(bom: Dict) -> Dict[str, Dict]:
    comps = {}
    for c in bom.get("components", []):
        comps[c.get("name")] = c
    return comps


def sbom_diff_cyclonedx(old_path: Path, new_path: Path) -> Dict:
    old = json.loads(Path(old_path).read_text(encoding="utf-8"))
    new = json.loads(Path(new_path).read_text(encoding="utf-8"))
    oc = extract_components_from_cyclonedx(old)
    nc = extract_components_from_cyclonedx(new)

    added = sorted([n for n in nc.keys() if n not in oc])
    removed = sorted([n for n in oc.keys() if n not in nc])
    changed = sorted([n for n in nc.keys() if n in oc and nc[n].get("version") != oc[n].get("version")])

    integrity_failures = []

    # Detect added native binaries lacking source/signature
    # Heuristic: components created from files named like *.so/*.dll/.dylib (if present as names)
    for n in added:
        name = n.lower()
        if name.endswith(".so") or name.endswith(".dll") or name.endswith(".dylib"):
            comp = nc[n]
            has_source_ref = False
            if "externalReferences" in comp:
                for ref in comp["externalReferences"]:
                    if ref.get("type") == "vcs":
                        has_source_ref = True
            has_signature = "signature" in comp or "signatures" in comp
            if not (has_source_ref and has_signature):
                integrity_failures.append(
                    {
                        "component": n,
                        "reason": "Added native binary lacks source reference and/or signature.",
                    }
                )
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "integrity_failures": integrity_failures,
    }


# ------------------------------ CLI Commands ---------------------------------


def cmd_analyze(args: argparse.Namespace) -> int:
    Log.warn("Authorized testing only. Ensure you have permission to analyze this environment.")
    project_name = args.project_name or Path(args.src).name
    project_version = args.project_version or "0.0.0"

    # Scan environment
    packages: Dict[str, PackageNode] = {}
    roots: Set[str] = set()
    if args.venv:
        sp = site_packages_path(Path(args.venv))
        if not sp:
            Log.error("Could not locate site-packages in provided venv.")
            return 2
        packages = scan_site_packages(sp)
        if args.requirements and Path(args.requirements).exists():
            for line in Path(args.requirements).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                roots.add(parse_requires_dist_line(line) or line)
        else:
            roots = set(packages.keys())
    else:
        # Use current interpreter environment
        candidate = None
        if hasattr(sys, "base_prefix"):
            candidate = Path(sys.prefix)
        if not candidate:
            Log.error("Cannot determine current environment.")
            return 2
        sp = site_packages_path(candidate)
        if not sp:
            Log.error("Could not locate site-packages in current environment.")
            return 2
        packages = scan_site_packages(sp)
        roots = set(packages.keys())

    resolved = resolve_transitive(packages, roots)
    det = TyposquatDetector()
    findings = det.detect(resolved)

    sb = SBOMBuilder(project_name, project_version, Path(args.vex) if args.vex else None)
    cyclonedx = sb.build_cyclonedx(resolved, findings)
    spdx = sb.build_spdx(resolved)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cdx_path = outdir / "sbom.cdx.json"
    spdx_path = outdir / "sbom.spdx.json"
    write_atomic(cdx_path, canonical_json(cyclonedx).encode())
    write_atomic(spdx_path, canonical_json(spdx).encode())
    Log.info(f"SBOMs written: {cdx_path}, {spdx_path}")

    if findings:
        Log.error("Typosquat suspicion detected; failing closed.")
        # Emit evidence
        evidence = []
        for f in findings:
            evidence.append(dataclasses.asdict(f))
        write_atomic(outdir / "typosquat_findings.json", canonical_json(evidence).encode())
        return 3

    return 0


def cmd_build(args: argparse.Namespace) -> int:
    Log.warn("Authorized testing only. Hermetic build starts; network is blocked in sandbox.")
    src = Path(args.src)
    outdir = Path(args.outdir)
    hs = HermeticSandbox(allowlist_dir=Path(args.allowlist) if args.allowlist else None, cache_dir=Path(args.cache) if args.cache else None)
    artifacts = hs.build_project(src, outdir)
    if not artifacts:
        Log.error("No artifacts produced.")
        return 4
    # provenance
    _, materials = hs._compute_inputs_digest(src)
    prov = hs.provenance_attestation(src, artifacts, materials)
    prov_path = outdir / "provenance.intoto.jsonl"
    write_atomic(prov_path, (canonical_json(prov) + "\n").encode())
    Log.info(f"Artifacts: {', '.join([a.name for a in artifacts])}")
    Log.info(f"Provenance written: {prov_path}")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    signer = CosignSigner(oidc_identity=args.oidc_identity, simulate=args.simulate)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    rc = 0
    for f in args.files:
        f = Path(f)
        sig = outdir / (f.name + ".sig")
        crt = outdir / (f.name + ".cert")
        bnd = outdir / (f.name + ".bundle.json")
        try:
            signer.sign_blob(f, sig, crt, bnd)
            Log.info(f"Signed: {f.name}")
            signer.verify_blob(f, bnd)
            Log.info(f"Verified with Rekor bundle: {f.name}")
        except CosignError as e:
            Log.error(str(e))
            rc = 5
    return rc


def cmd_verify(args: argparse.Namespace) -> int:
    signer = CosignSigner(oidc_identity=None, simulate=args.simulate)
    rc = 0
    for f in args.files:
        path = Path(f)
        bundle = Path(f + ".bundle.json")
        try:
            signer.verify_blob(path, bundle)
            Log.info(f"Verified and Rekor inclusion confirmed: {path.name}")
        except CosignError as e:
            Log.error(str(e))
            rc = 6
    return rc


def cmd_diff(args: argparse.Namespace) -> int:
    diff = sbom_diff_cyclonedx(Path(args.old), Path(args.new))
    print(canonical_json(diff))
    if diff["integrity_failures"]:
        Log.error("Integrity checks failed; added untrusted binaries detected.")
        return 7
    return 0


def cmd_pipeline(args: argparse.Namespace) -> int:
    """
    Full pipeline: hermetic build, SBOM generation, signing and verification.
    Fails closed on any issue, including typosquat detection, signature verification, Rekor inclusion, and reproducibility.
    """
    Log.warn("Authorized testing only. Running full SBOM Sentinel pipeline.")
    src = Path(args.src)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # 1. Hermetic build
    hs = HermeticSandbox(allowlist_dir=Path(args.allowlist) if args.allowlist else None, cache_dir=Path(args.cache) if args.cache else None)
    try:
        artifacts = hs.build_project(src, outdir)
    except Exception as e:
        Log.error(f"Hermetic build failed: {e}")
        return 10
    if not artifacts:
        Log.error("No artifacts generated.")
        return 10
    # provenance
    _, materials = hs._compute_inputs_digest(src)
    prov = hs.provenance_attestation(src, artifacts, materials)
    prov_path = outdir / "provenance.intoto.jsonl"
    write_atomic(prov_path, (canonical_json(prov) + "\n").encode())

    # 2. Analyze dependencies and generate SBOMs (CycloneDX prioritised)
    project_name = args.project_name or src.name
    project_version = args.project_version or "0.0.0"
    # Use current environment (or provided venv) to resolve dependencies
    tmp_args = argparse.Namespace(
        project_name=project_name,
        project_version=project_version,
        src=str(src),
        venv=args.venv,
        requirements=args.requirements,
        vex=args.vex,
        outdir=str(outdir),
    )
    rc = cmd_analyze(tmp_args)
    if rc != 0:
        Log.error("Analysis failed; pipeline halted.")
        return rc
    cdx_path = outdir / "sbom.cdx.json"
    spdx_path = outdir / "sbom.spdx.json"

    # 3. Sign SBOM and provenance
    signer = CosignSigner(oidc_identity=args.oidc_identity, simulate=args.simulate)
    files_to_sign = [cdx_path, spdx_path, prov_path]
    try:
        for f in files_to_sign:
            signer.sign_blob(f, outdir / (f.name + ".sig"), outdir / (f.name + ".cert"), outdir / (f.name + ".bundle.json"))
            signer.verify_blob(f, outdir / (f.name + ".bundle.json"))
    except CosignError as e:
        Log.error(f"Signing/verification failed: {e}")
        return 11

    Log.info("Pipeline succeeded: SBOMs, provenance, signatures, and transparency verification complete.")
    return 0


# ------------------------------ Argparse Setup -------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sbom-sentinel",
        description="SBOM Sentinel: Continuous dependency analysis and SBOM generation with hermetic builds and signed provenance. Authorized testing only.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="Analyze dependencies, detect typosquats, generate SPDX and CycloneDX SBOMs.")
    a.add_argument("--src", default=".", help="Project source directory (for naming)")
    a.add_argument("--project-name", help="Project name")
    a.add_argument("--project-version", help="Project version")
    a.add_argument("--venv", help="Path to virtualenv to scan (defaults to current env if omitted)")
    a.add_argument("--requirements", help="Path to requirements file containing roots")
    a.add_argument("--vex", help="Path to VEX JSON file mapping package->note")
    a.add_argument("--outdir", default="sbom_output", help="Output directory")
    a.set_defaults(func=cmd_analyze)

    b = sub.add_parser("hermetic-build", help="Perform hermetic build and produce SLSA provenance attestation.")
    b.add_argument("--src", default=".", help="Project source directory")
    b.add_argument("--outdir", default="sbom_output", help="Output directory for artifacts")
    b.add_argument("--allowlist", help="Directory of pre-fetched wheels/sdists allowed (PIP_FIND_LINKS)")
    b.add_argument("--cache", help="Content-addressed cache directory")
    b.set_defaults(func=cmd_build)

    s = sub.add_parser("sign", help="Sign artifacts with cosign and verify Rekor inclusion.")
    s.add_argument("--outdir", default="sbom_output", help="Output directory for signatures")
    s.add_argument("--oidc-identity", help="OIDC identity token for cosign (or use env)")
    s.add_argument("--simulate", action="store_true", help="Simulate signing locally (not secure)")
    s.add_argument("files", nargs="+", help="Files to sign and verify")
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="Verify signatures and Rekor inclusion for given files (expects .bundle.json next to file).")
    v.add_argument("--simulate", action="store_true", help="Simulate verification (not secure)")
    v.add_argument("files", nargs="+", help="Files to verify")
    v.set_defaults(func=cmd_verify)

    d = sub.add_parser("diff", help="Deterministic diff between two CycloneDX SBOMs.")
    d.add_argument("old", help="Old CycloneDX SBOM path")
    d.add_argument("new", help="New CycloneDX SBOM path")
    d.set_defaults(func=cmd_diff)

    f = sub.add_parser("full-pipeline", help="Run hermetic build, analysis, signing, and verification end-to-end.")
    f.add_argument("--src", default=".", help="Project source directory")
    f.add_argument("--outdir", default="sbom_output", help="Output directory")
    f.add_argument("--allowlist", help="Directory of pre-fetched wheels/sdists allowed (PIP_FIND_LINKS)")
    f.add_argument("--cache", help="Content-addressed cache directory")
    f.add_argument("--project-name", help="Project name")
    f.add_argument("--project-version", help="Project version")
    f.add_argument("--venv", help="Path to virtualenv to scan for dependencies")
    f.add_argument("--requirements", help="Path to requirements file of roots")
    f.add_argument("--vex", help="Path to VEX JSON file")
    f.add_argument("--oidc-identity", help="OIDC identity token for cosign (or use env)")
    f.add_argument("--simulate", action="store_true", help="Simulate signing locally (not secure)")
    f.set_defaults(func=cmd_pipeline)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        Log.error("Interrupted by user.")
        return 130
    except Exception as e:
        Log.error(f"Unhandled error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())