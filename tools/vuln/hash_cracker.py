#!/usr/bin/env python3
import argparse
import hashlib
import itertools
import json
import math
import os
import re
import sys
import time
from typing import Callable, Dict, List, Optional, Tuple

try:
    import bcrypt as bcrypt_lib  # type: ignore
    HAS_BCRYPT = True
except Exception:
    bcrypt_lib = None
    HAS_BCRYPT = False

ETHICAL_WARNING = """WARNING: Authorized testing only!
This hash cracking tool is intended solely for lawful security testing,
password recovery for systems you own, or where you have explicit permission.
Unauthorized use may violate laws and regulations. Use responsibly.
"""

DEFAULT_SYMBOLS = r"""!@#$%^&*()-_=+[]{};:'",.<>/?\|`~"""

# --------------- Utility functions ---------------

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def seconds_to_hms(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def is_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))

def detect_hash_type(hash_str: str) -> Optional[str]:
    hs = hash_str.strip()
    # bcrypt
    if hs.startswith("$2a$") or hs.startswith("$2b$") or hs.startswith("$2y$"):
        return "bcrypt"
    # hex length based
    if is_hex(hs):
        l = len(hs)
        if l == 32:
            return "md5"
        if l == 40:
            return "sha1"
        if l == 64:
            return "sha256"
        if l == 128:
            return "sha512"
    return None

def validate_hash(hash_str: str, algo: str) -> Tuple[bool, Optional[str]]:
    hs = hash_str.strip()
    if algo == "bcrypt":
        if not (hs.startswith("$2a$") or hs.startswith("$2b$") or hs.startswith("$2y$")):
            return False, "Invalid bcrypt format. Expected hash starting with $2a$, $2b$, or $2y$."
        parts = hs.split("$")
        if len(parts) < 4:
            return False, "Invalid bcrypt format."
        return True, None
    else:
        expected_lengths = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
        exp = expected_lengths.get(algo)
        if exp is None:
            return False, f"Unsupported algorithm: {algo}"
        if len(hs) != exp or not is_hex(hs):
            return False, f"Invalid {algo} hash format. Expected {exp}-character hexadecimal string."
        return True, None

def compute_digest(algo: str, plaintext: str, encoding: str = "utf-8") -> str:
    data = plaintext.encode(encoding, errors="ignore")
    if algo == "md5":
        return hashlib.md5(data).hexdigest()
    if algo == "sha1":
        return hashlib.sha1(data).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(data).hexdigest()
    if algo == "sha512":
        return hashlib.sha512(data).hexdigest()
    raise ValueError(f"Unsupported digest algorithm: {algo}")

def verify_candidate(algo: str, hash_str: str, candidate: str, encoding: str = "utf-8") -> bool:
    if algo == "bcrypt":
        if not HAS_BCRYPT:
            raise RuntimeError("bcrypt support is not available (missing 'bcrypt' library).")
        try:
            return bcrypt_lib.checkpw(candidate.encode(encoding, errors="ignore"), hash_str.encode("utf-8"))
        except Exception:
            return False
    else:
        return compute_digest(algo, candidate, encoding).lower() == hash_str.lower()

def parse_charset(spec: str, extra: str = "") -> str:
    parts = [p.strip().lower() for p in spec.split(",") if p.strip()]
    charset = ""
    for p in parts:
        if p == "lower":
            charset += "abcdefghijklmnopqrstuvwxyz"
        elif p == "upper":
            charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        elif p == "digits":
            charset += "0123456789"
        elif p == "symbols":
            charset += DEFAULT_SYMBOLS
        else:
            # treat as literal characters
            charset += p
    charset += extra
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for ch in charset:
        if ch not in seen:
            seen.add(ch)
            unique.append(ch)
    return "".join(unique)

def count_lines_in_file(path: str) -> int:
    count = 0
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                count += chunk.count(b"\n")
        # If last line doesn't end with newline, it still counts as a line when read textually.
        # To be safe, open as text to check if file non-empty and last char not newline; but skip to keep simple.
        # It's acceptable that count may be off by 1 in rare cases; we can correct while reading in progress.
        # We'll adjust dynamically during processing.
    except Exception:
        # fallback slow path
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for _ in f:
                    count += 1
        except Exception:
            pass
    return count

def hr_number(n: float) -> str:
    units = ["", "K", "M", "G", "T"]
    i = 0
    while n >= 1000 and i < len(units) - 1:
        n /= 1000.0
        i += 1
    if n >= 100:
        return f"{n:,.0f}{units[i]}"
    if n >= 10:
        return f"{n:,.1f}{units[i]}"
    return f"{n:,.2f}{units[i]}"

# --------------- Progress and resume ---------------

class Progress:
    def __init__(self, total: Optional[int], interval_sec: float = 1.0, mode: str = "wordlist"):
        self.total = total
        self.interval = max(0.2, interval_sec)
        self.mode = mode
        self.attempts = 0
        self.start_time = time.time()
        self.last_print = 0.0

    def tick(self, n: int = 1):
        self.attempts += n

    def maybe_print(self, prefix: str = ""):
        now = time.time()
        if now - self.last_print >= self.interval:
            self.last_print = now
            elapsed = now - self.start_time
            rate = self.attempts / elapsed if elapsed > 0 else 0.0
            if self.total is not None and self.total > 0:
                pct = min(100.0, (self.attempts / self.total) * 100.0)
                remaining = max(0, self.total - self.attempts)
                eta = remaining / rate if rate > 0 else float("inf")
                msg = f"{prefix}Progress [{self.mode}] {self.attempts}/{self.total} ({pct:0.2f}%) at {hr_number(rate)}/s, elapsed {seconds_to_hms(elapsed)}, ETA {seconds_to_hms(eta)}"
            else:
                msg = f"{prefix}Progress [{self.mode}] {self.attempts} attempts at {hr_number(rate)}/s, elapsed {seconds_to_hms(elapsed)}"
            eprint(msg)

class ResumeManager:
    def __init__(self, resume_file: Optional[str]):
        self.resume_file = resume_file

    @staticmethod
    def make_default_path(config_id: str) -> str:
        return f".hash_cracker_resume_{config_id}.json"

    def load(self) -> Optional[Dict]:
        if not self.resume_file:
            return None
        try:
            if os.path.exists(self.resume_file):
                with open(self.resume_file, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            return None
        return None

    def save(self, data: Dict):
        if not self.resume_file:
            return
        try:
            with open(self.resume_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def reset(self):
        if self.resume_file and os.path.exists(self.resume_file):
            try:
                os.remove(self.resume_file)
            except Exception:
                pass

# --------------- Wordlist attack ---------------

def wordlist_attack(
    hash_str: str,
    algo: str,
    wordlist_paths: List[str],
    encoding: str,
    progress: Progress,
    resume: Optional[Dict],
    resume_mgr: ResumeManager,
    save_interval_sec: float = 5.0,
) -> Tuple[Optional[str], int]:
    file_index = 0
    line_number = 0  # number of lines already processed in current file
    attempts = 0
    total_lines = None
    last_save = time.time()

    # Pre-count total lines for progress
    try:
        counts = [count_lines_in_file(p) for p in wordlist_paths]
        total_lines = sum(counts)
        progress.total = total_lines
    except Exception:
        total_lines = None

    if resume and resume.get("state", {}).get("mode") == "wordlist":
        st = resume["state"]
        file_index = int(st.get("file_index", 0))
        line_number = int(st.get("line_number", 0))
        attempts = int(resume.get("attempts", 0))
        progress.attempts = attempts

    for fi in range(file_index, len(wordlist_paths)):
        path = wordlist_paths[fi]
        if not os.path.isfile(path):
            eprint(f"[!] Wordlist not found: {path}")
            continue
        try:
            with open(path, "r", encoding=encoding, errors="ignore") as f:
                # Skip lines if resuming within this file
                skipped = 0
                if fi == file_index and line_number > 0:
                    for _ in range(line_number):
                        if f.readline() == "":
                            break
                        skipped += 1
                    # adjust attempts/progress if pre-count was off
                    progress.tick(skipped)
                current_line = line_number
                for line in f:
                    candidate = line.rstrip("\r\n")
                    attempts += 1
                    progress.tick(1)
                    if verify_candidate(algo, hash_str, candidate, encoding):
                        # Save final state
                        resume_mgr.save({
                            "meta": {
                                "mode": "wordlist",
                                "algo": algo,
                                "hash": hash_str,
                            },
                            "state": {
                                "mode": "wordlist",
                                "file_index": fi,
                                "line_number": current_line + 1,
                            },
                            "attempts": attempts,
                            "updated_at": time.time(),
                            "cracked": True,
                            "password": candidate,
                        })
                        return candidate, attempts
                    current_line += 1
                    now = time.time()
                    if now - last_save >= save_interval_sec:
                        resume_mgr.save({
                            "meta": {
                                "mode": "wordlist",
                                "algo": algo,
                                "hash": hash_str,
                            },
                            "state": {
                                "mode": "wordlist",
                                "file_index": fi,
                                "line_number": current_line,
                            },
                            "attempts": attempts,
                            "updated_at": now,
                        })
                        last_save = now
                    progress.maybe_print()
        except KeyboardInterrupt:
            eprint("\n[!] Interrupted by user. Saving progress...")
            resume_mgr.save({
                "meta": {
                    "mode": "wordlist",
                    "algo": algo,
                    "hash": hash_str,
                },
                "state": {
                    "mode": "wordlist",
                    "file_index": fi,
                    "line_number": current_line if 'current_line' in locals() else line_number,
                },
                "attempts": attempts,
                "updated_at": time.time(),
            })
            raise
        except Exception as ex:
            eprint(f"[!] Error reading '{path}': {ex}")
    # Not found
    resume_mgr.save({
        "meta": {
            "mode": "wordlist",
            "algo": algo,
            "hash": hash_str,
        },
        "state": {
            "mode": "wordlist",
            "file_index": len(wordlist_paths),
            "line_number": 0,
        },
        "attempts": attempts,
        "updated_at": time.time(),
        "cracked": False,
    })
    return None, attempts

# --------------- Brute force attack ---------------

def number_to_password(pos: int, charset: str, length: int) -> str:
    # base-N conversion with leading zeros to ensure fixed length
    n = len(charset)
    chars = []
    v = pos
    for _ in range(length):
        chars.append(charset[v % n])
        v //= n
    return "".join(reversed(chars))

def brute_force_totals(n_charset: int, min_len: int, max_len: int) -> int:
    total = 0
    for L in range(min_len, max_len + 1):
        total += int(pow(n_charset, L))
    return total

def brute_force_attack(
    hash_str: str,
    algo: str,
    charset: str,
    min_len: int,
    max_len: int,
    encoding: str,
    progress: Progress,
    resume: Optional[Dict],
    resume_mgr: ResumeManager,
    save_interval_sec: float = 5.0,
) -> Tuple[Optional[str], int]:
    n = len(charset)
    if n == 0:
        raise ValueError("Empty charset for brute force.")
    attempts = 0
    curr_len = min_len
    position = 0  # position within current length
    last_save = time.time()

    total = brute_force_totals(n, min_len, max_len)
    progress.total = total

    if resume and resume.get("state", {}).get("mode") == "bruteforce":
        st = resume["state"]
        curr_len = int(st.get("current_length", min_len))
        position = int(st.get("position", 0))
        attempts = int(resume.get("attempts", 0))
        progress.attempts = attempts

    for L in range(curr_len, max_len + 1):
        start_pos = position if L == curr_len else 0
        max_pos = int(pow(n, L))
        pos = start_pos
        while pos < max_pos:
            candidate = number_to_password(pos, charset, L)
            attempts += 1
            progress.tick(1)
            if verify_candidate(algo, hash_str, candidate, encoding):
                resume_mgr.save({
                    "meta": {
                        "mode": "bruteforce",
                        "algo": algo,
                        "hash": hash_str,
                    },
                    "state": {
                        "mode": "bruteforce",
                        "current_length": L,
                        "position": pos + 1,
                        "charset": charset,
                        "min_len": min_len,
                        "max_len": max_len,
                    },
                    "attempts": attempts,
                    "updated_at": time.time(),
                    "cracked": True,
                    "password": candidate,
                })
                return candidate, attempts
            pos += 1
            now = time.time()
            if now - last_save >= save_interval_sec:
                resume_mgr.save({
                    "meta": {
                        "mode": "bruteforce",
                        "algo": algo,
                        "hash": hash_str,
                    },
                    "state": {
                        "mode": "bruteforce",
                        "current_length": L,
                        "position": pos,
                        "charset": charset,
                        "min_len": min_len,
                        "max_len": max_len,
                    },
                    "attempts": attempts,
                    "updated_at": now,
                })
                last_save = now
            progress.maybe_print()
    resume_mgr.save({
        "meta": {
            "mode": "bruteforce",
            "algo": algo,
            "hash": hash_str,
        },
        "state": {
            "mode": "bruteforce",
            "current_length": max_len,
            "position": int(pow(n, max_len)),
            "charset": charset,
            "min_len": min_len,
            "max_len": max_len,
        },
        "attempts": attempts,
        "updated_at": time.time(),
        "cracked": False,
    })
    return None, attempts

# --------------- Main CLI ---------------

def config_id_from_params(hash_str: str, algo: str, mode: str, extras: str) -> str:
    base = f"{hash_str}|{algo}|{mode}|{extras}"
    hid = hashlib.sha1(base.encode("utf-8")).hexdigest()
    return hid[:12]

def main():
    parser = argparse.ArgumentParser(
        description="Hash Cracker Suite: Multi-algorithm hash cracking tool with wordlist and brute force attacks"
    )
    parser.add_argument("--hash", dest="hash_str", required=True, help="Target hash to crack")
    parser.add_argument("--algo", choices=["md5", "sha1", "sha256", "sha512", "bcrypt"], help="Hash algorithm. If omitted, tool will try to detect.")
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--wordlist", nargs="+", help="Wordlist file(s) for dictionary attack")
    mode_group.add_argument("--bruteforce", action="store_true", help="Enable brute force mode")

    parser.add_argument("--encoding", default="utf-8", help="Encoding for wordlists (default: utf-8)")
    parser.add_argument("--progress-interval", type=float, default=1.0, help="Progress update interval in seconds")
    parser.add_argument("--resume", action="store_true", default=False, help="Resume from saved state and save progress")
    parser.add_argument("--resume-file", help="Custom resume state file path")
    parser.add_argument("--reset-resume", action="store_true", help="Reset (delete) resume state before starting")
    parser.add_argument("--save-results", help="File to append cracked results (hash:password) on success")
    parser.add_argument("--quiet", action="store_true", help="Suppress ethical warning banner")

    # Brute force options
    parser.add_argument("--charset", default="lower,digits", help="Character set spec: lower,upper,digits,symbols or literal chars separated by commas")
    parser.add_argument("--extra-chars", default="", help="Additional characters to include in charset")
    parser.add_argument("--min-length", type=int, default=1, help="Minimum password length for brute force")
    parser.add_argument("--max-length", type=int, default=4, help="Maximum password length for brute force")

    args = parser.parse_args()

    if not args.quiet:
        eprint(ETHICAL_WARNING)

    hash_str = args.hash_str.strip()
    algo = args.algo
    detected = detect_hash_type(hash_str)
    if algo is None:
        if detected is None:
            eprint("[!] Could not automatically detect hash type. Please specify --algo.")
            sys.exit(2)
        algo = detected
        eprint(f"[i] Detected hash algorithm: {algo}")
    else:
        # If user specified and detection differs (for non-bcrypt), warn
        if detected and detected != algo:
            eprint(f"[!] Warning: hash format suggests '{detected}', but --algo is '{algo}'. Proceeding with '{algo}'.")

    ok, err = validate_hash(hash_str, algo)
    if not ok:
        eprint(f"[!] {err}")
        sys.exit(2)

    if algo == "bcrypt" and not HAS_BCRYPT:
        eprint("[!] bcrypt algorithm requested but 'bcrypt' library is not installed. Install with: pip install bcrypt")
        # Still allow running wordlist mode to report failures gracefully
        # but verification will raise at first candidate; handle gracefully later.

    mode = "wordlist" if args.wordlist else "bruteforce"

    extras = ""
    if mode == "wordlist":
        wl_paths = args.wordlist
        # Expand directory to files if necessary
        expanded: List[str] = []
        for p in wl_paths:
            if os.path.isdir(p):
                try:
                    for name in sorted(os.listdir(p)):
                        fp = os.path.join(p, name)
                        if os.path.isfile(fp):
                            expanded.append(fp)
                except Exception:
                    pass
            else:
                expanded.append(p)
        if not expanded:
            eprint("[!] No valid wordlist files found.")
            sys.exit(2)
        args.wordlist = expanded
        extras = "|".join(expanded)
    else:
        charset = parse_charset(args.charset, args.extra_chars)
        if len(charset) == 0:
            eprint("[!] Empty charset after parsing. Adjust --charset/--extra-chars.")
            sys.exit(2)
        if args.min_length <= 0 or args.max_length <= 0 or args.min_length > args.max_length:
            eprint("[!] Invalid length range for brute force. Ensure 0 < min <= max.")
            sys.exit(2)
        # Warn if search space is enormous
        space = brute_force_totals(len(charset), args.min_length, args.max_length)
        if space > 10_000_000:
            eprint(f"[!] Caution: brute force search space is large: {space:,} candidates.")
        extras = f"charset={charset}|min={args.min_length}|max={args.max_length}"

    cfg_id = config_id_from_params(hash_str, algo, mode, extras)
    resume_path = args.resume_file if args.resume_file else (ResumeManager.make_default_path(cfg_id) if args.resume else None)
    resume_mgr = ResumeManager(resume_path)

    if args.reset_resume and resume_mgr.resume_file:
        resume_mgr.reset()
        eprint(f"[i] Cleared resume state at {resume_mgr.resume_file}")

    resume_data = resume_mgr.load() if args.resume else None
    if args.resume and resume_mgr.resume_file:
        eprint(f"[i] Resume file: {resume_mgr.resume_file}")

    progress = Progress(total=None, interval_sec=args.progress_interval, mode=mode)

    cracked = None
    attempts = 0

    try:
        if mode == "wordlist":
            cracked, attempts = wordlist_attack(
                hash_str=hash_str,
                algo=algo,
                wordlist_paths=args.wordlist,
                encoding=args.encoding,
                progress=progress,
                resume=resume_data,
                resume_mgr=resume_mgr,
            )
        else:
            cracked, attempts = brute_force_attack(
                hash_str=hash_str,
                algo=algo,
                charset=parse_charset(args.charset, args.extra_chars),
                min_len=args.min_length,
                max_len=args.max_length,
                encoding=args.encoding,
                progress=progress,
                resume=resume_data,
                resume_mgr=resume_mgr,
            )
    except KeyboardInterrupt:
        eprint("[!] Cracking interrupted by user.")
        sys.exit(130)
    except RuntimeError as ex:
        eprint(f"[!] Runtime error: {ex}")
        sys.exit(1)
    except Exception as ex:
        eprint(f"[!] Unexpected error: {ex}")
        sys.exit(1)

    if cracked is not None:
        print(f"Cracked: {cracked}")
        if args.save_results:
            try:
                with open(args.save_results, "a", encoding="utf-8") as f:
                    f.write(f"{hash_str}:{cracked}\n")
            except Exception as ex:
                eprint(f"[!] Failed to save results: {ex}")
        sys.exit(0)
    else:
        eprint(f"[i] Password not found. Attempts: {attempts}")
        sys.exit(3)

if __name__ == "__main__":
    main()