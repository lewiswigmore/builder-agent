#!/usr/bin/env python3
"""
Hash Cracker Suite - Multi-algorithm hash cracking tool with wordlist and brute force attacks.

Features:
- Supports MD5, SHA1, SHA256, SHA512, bcrypt
- Wordlist-based attacks with custom lists
- Brute force with configurable character sets and lengths
- Hash format detection
- Progress tracking and resume capability

Ethical Warning:
This tool is intended strictly for authorized security testing, research, and educational purposes.
Do not use it on systems, accounts, or data that you do not own or have explicit written permission to test.
Misuse may be illegal and unethical.

Usage examples:
- Wordlist attack with auto-detection:
  python tools/vuln/hash_cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --attack wordlist --wordlist /path/to/rockyou.txt

- Brute force attack (lowercase letters, digits, length 1-6):
  python tools/vuln/hash_cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --attack bruteforce --lower --digits --min-length 1 --max-length 6

- Resume a previous session:
  python tools/vuln/hash_cracker.py --resume --resume-file ./resume_state.json
"""
import argparse
import hashlib
import json
import os
import re
import signal
import sys
import time
from dataclasses import dataclass, asdict
from typing import Optional, Tuple, Iterable


SUPPORTED_ALGOS = ["md5", "sha1", "sha256", "sha512", "bcrypt"]


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def detect_hash_algorithm(hash_str: str) -> Optional[str]:
    """
    Detect hash algorithm based on string characteristics.
    - bcrypt: starts with $2a$, $2b$, $2y$
    - md5: 32 hex
    - sha1: 40 hex
    - sha256: 64 hex
    - sha512: 128 hex
    Returns algo name or None if unknown.
    """
    if not hash_str:
        return None
    hs = hash_str.strip()
    if hs.startswith("$2a$") or hs.startswith("$2b$") or hs.startswith("$2y$"):
        return "bcrypt"
    # Hex detection tolerant of upper-case hex
    hex_re = re.compile(r"^[0-9a-fA-F]+$")
    if hex_re.match(hs):
        length = len(hs)
        if length == 32:
            return "md5"
        if length == 40:
            return "sha1"
        if length == 64:
            return "sha256"
        if length == 128:
            return "sha512"
    return None


def hash_candidate(candidate: str, algo: str, target_hash: str) -> bool:
    """
    Check if candidate matches target_hash for the given algo.
    For bcrypt, uses bcrypt.checkpw which handles salt embedded in hash.
    """
    if algo not in SUPPORTED_ALGOS:
        raise ValueError(f"Unsupported algorithm: {algo}")
    if algo == "bcrypt":
        try:
            import bcrypt  # type: ignore
        except Exception as ex:
            raise RuntimeError("bcrypt module not available. Install with: pip install bcrypt") from ex
        try:
            return bcrypt.checkpw(candidate.encode("utf-8", errors="ignore"), target_hash.encode("utf-8"))
        except Exception:
            return False
    else:
        data = candidate.encode("utf-8", errors="ignore")
        if algo == "md5":
            h = hashlib.md5()
        elif algo == "sha1":
            h = hashlib.sha1()
        elif algo == "sha256":
            h = hashlib.sha256()
        elif algo == "sha512":
            h = hashlib.sha512()
        else:
            raise ValueError(f"Unsupported algorithm: {algo}")
        h.update(data)
        computed = h.hexdigest()
        # Allow case-insensitive comparison for hex
        return computed.lower() == target_hash.lower()


@dataclass
class WordlistState:
    path: str = ""
    line_index: int = 0
    total_lines: Optional[int] = None


@dataclass
class BruteforceState:
    charset: str = ""
    min_length: int = 1
    max_length: int = 1
    current_length: int = 1
    position: int = 0  # index within current length


@dataclass
class ResumeState:
    version: int = 1
    hash: str = ""
    algo: str = ""
    attack: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    attempts: int = 0
    progress_total: Optional[int] = None
    found: bool = False
    found_plain: Optional[str] = None
    wordlist: Optional[WordlistState] = None
    bruteforce: Optional[BruteforceState] = None

    def to_json(self) -> str:
        def default(o):
            if isinstance(o, (ResumeState, WordlistState, BruteforceState)):
                return asdict(o)
            raise TypeError(f"Object of type {type(o)} is not JSON serializable")
        return json.dumps(self, default=default, indent=2, sort_keys=True)

    @staticmethod
    def from_file(path: str) -> "ResumeState":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        rs = ResumeState(
            version=data.get("version", 1),
            hash=data.get("hash", ""),
            algo=data.get("algo", ""),
            attack=data.get("attack", ""),
            created_at=data.get("created_at", 0.0),
            updated_at=data.get("updated_at", 0.0),
            attempts=int(data.get("attempts", 0)),
            progress_total=data.get("progress_total"),
            found=bool(data.get("found", False)),
            found_plain=data.get("found_plain"),
        )
        wl = data.get("wordlist")
        if wl:
            rs.wordlist = WordlistState(
                path=wl.get("path", ""),
                line_index=int(wl.get("line_index", 0)),
                total_lines=wl.get("total_lines"),
            )
        bf = data.get("bruteforce")
        if bf:
            rs.bruteforce = BruteforceState(
                charset=bf.get("charset", ""),
                min_length=int(bf.get("min_length", 1)),
                max_length=int(bf.get("max_length", 1)),
                current_length=int(bf.get("current_length", 1)),
                position=int(bf.get("position", 0)),
            )
        return rs

    def save(self, path: str) -> None:
        self.updated_at = time.time()
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        os.replace(tmp_path, path)


class ProgressTracker:
    def __init__(self, total: Optional[int], interval: float = 1.0, quiet: bool = False):
        self.total = total
        self.interval = interval
        self.quiet = quiet
        self.attempts = 0
        self.start_time = time.time()
        self.last_print = 0.0

    def increment(self, n: int = 1):
        self.attempts += n

    def format_eta(self) -> str:
        elapsed = time.time() - self.start_time
        if self.attempts == 0:
            return "ETA: --:--:--"
        rate = self.attempts / max(elapsed, 1e-9)
        if self.total is None or self.total <= 0:
            return f"{rate:.1f} H/s"
        remaining = max(self.total - self.attempts, 0)
        if rate <= 0:
            return "ETA: --:--:--"
        sec = remaining / rate
        h = int(sec // 3600)
        m = int((sec % 3600) // 60)
        s = int(sec % 60)
        return f"{rate:.1f} H/s, ETA: {h:02d}:{m:02d}:{s:02d}"

    def maybe_print(self, prefix: str = ""):
        if self.quiet:
            return
        now = time.time()
        if (now - self.last_print) >= self.interval:
            self.last_print = now
            if self.total is not None and self.total > 0:
                percent = (self.attempts / self.total) * 100.0 if self.total else 0.0
                eprint(f"{prefix}Progress: {self.attempts}/{self.total} ({percent:.2f}%) | {self.format_eta()}")
            else:
                eprint(f"{prefix}Progress: {self.attempts} attempts | {self.format_eta()}")


def count_lines(filepath: str) -> int:
    """Count lines in a file efficiently."""
    cnt = 0
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            cnt += block.count(b"\n")
    return cnt


def generate_bruteforce_candidates(charset: str, min_length: int, max_length: int,
                                   start_length: Optional[int] = None, start_position: int = 0) -> Iterable[Tuple[str, int, int]]:
    """
    Generate brute force candidates.
    Yields tuples: (candidate, current_length, position_within_length)
    start_length: the length to start from
    start_position: index within that length (0-based)
    """
    chars = charset
    base = len(chars)
    if base <= 0:
        return
    for length in range(min_length, max_length + 1):
        if start_length is not None and length < start_length:
            continue
        # Determine starting index for this length
        pos_start = start_position if (start_length is not None and length == start_length) else 0
        max_pos = pow(base, length)
        for pos in range(pos_start, max_pos):
            # Convert pos to base 'base' number with 'length' digits
            n = pos
            indices = [0] * length
            for i in range(length - 1, -1, -1):
                indices[i] = n % base
                n //= base
            candidate = "".join(chars[idx] for idx in indices)
            yield candidate, length, pos


def bruteforce_total(charset: str, min_length: int, max_length: int) -> int:
    base = len(charset)
    if base <= 0 or min_length > max_length:
        return 0
    total = 0
    for l in range(min_length, max_length + 1):
        total += pow(base, l)
    return total


def sanitize_charset(chars: str) -> str:
    # Remove duplicates while preserving order
    seen = set()
    res = []
    for ch in chars:
        if ch not in seen:
            seen.add(ch)
            res.append(ch)
    return "".join(res)


def crack_wordlist(target_hash: str, algo: str, wordlist_path: str, progress_interval: float,
                   resume_state: Optional[ResumeState], resume_file: Optional[str], quiet: bool,
                   state_interval: float) -> Tuple[bool, Optional[str], ResumeState]:
    if not os.path.isfile(wordlist_path):
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    total = None
    try:
        total = count_lines(wordlist_path)
    except Exception:
        total = None

    # Initialize resume state
    if resume_state is None:
        resume_state = ResumeState(
            version=1,
            hash=target_hash,
            algo=algo,
            attack="wordlist",
            created_at=time.time(),
            updated_at=time.time(),
            attempts=0,
            progress_total=total,
            wordlist=WordlistState(path=wordlist_path, line_index=0, total_lines=total),
            bruteforce=None,
        )
    else:
        # Validate/merge
        if resume_state.attack != "wordlist":
            eprint("Resume file attack type differs. Starting new wordlist session.")
            resume_state = ResumeState(
                version=1,
                hash=target_hash,
                algo=algo,
                attack="wordlist",
                created_at=time.time(),
                updated_at=time.time(),
                attempts=0,
                progress_total=total,
                wordlist=WordlistState(path=wordlist_path, line_index=0, total_lines=total),
                bruteforce=None,
            )
        else:
            # If different path, reset line index
            if not resume_state.wordlist or resume_state.wordlist.path != wordlist_path:
                resume_state.wordlist = WordlistState(path=wordlist_path, line_index=0, total_lines=total)
                resume_state.attempts = 0
                resume_state.progress_total = total

    tracker = ProgressTracker(total=resume_state.progress_total, interval=progress_interval, quiet=quiet)

    # Pre-initialize attempts
    tracker.attempts = resume_state.attempts

    interrupted = False

    def handle_sigint(sig, frame):
        nonlocal interrupted
        interrupted = True
        eprint("\nInterrupted by user. Saving state...")

    old_handler = signal.signal(signal.SIGINT, handle_sigint)
    last_state_save = time.time()

    found_plain = None
    current_index = resume_state.wordlist.line_index if resume_state.wordlist else 0
    try:
        start_line = current_index
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            # Skip lines up to start_line
            for _ in range(start_line):
                if f.readline() == "":
                    break
            for line in f:
                if interrupted:
                    break
                candidate = line.rstrip("\r\n")
                current_index += 1
                tracker.increment()
                if candidate and hash_candidate(candidate, algo, target_hash):
                    found_plain = candidate
                    resume_state.found = True
                    resume_state.found_plain = candidate
                    resume_state.attempts = tracker.attempts
                    if resume_state.wordlist:
                        resume_state.wordlist.line_index = current_index
                    if resume_file:
                        resume_state.save(resume_file)
                    break
                # progress display
                tracker.maybe_print(prefix="[wordlist] ")
                # periodic save
                now = time.time()
                if resume_file and (now - last_state_save) >= state_interval:
                    if resume_state.wordlist:
                        resume_state.wordlist.line_index = current_index
                    resume_state.attempts = tracker.attempts
                    resume_state.progress_total = total
                    resume_state.save(resume_file)
                    last_state_save = now
    finally:
        # Restore previous signal handler
        signal.signal(signal.SIGINT, old_handler)

    # Final save
    if resume_file:
        if resume_state.wordlist:
            resume_state.wordlist.line_index = current_index
        resume_state.attempts = tracker.attempts
        resume_state.progress_total = total
        resume_state.save(resume_file)

    return (found_plain is not None), found_plain, resume_state


def crack_bruteforce(target_hash: str, algo: str, charset: str, min_length: int, max_length: int,
                     progress_interval: float, resume_state: Optional[ResumeState], resume_file: Optional[str],
                     quiet: bool, state_interval: float) -> Tuple[bool, Optional[str], ResumeState]:

    charset = sanitize_charset(charset)
    if not charset:
        raise ValueError("Empty charset. Specify at least one of --lower/--upper/--digits/--symbols or --charset.")

    total = bruteforce_total(charset, min_length, max_length)

    # Initialize or validate resume state
    if resume_state is None:
        resume_state = ResumeState(
            version=1,
            hash=target_hash,
            algo=algo,
            attack="bruteforce",
            created_at=time.time(),
            updated_at=time.time(),
            attempts=0,
            progress_total=total,
            wordlist=None,
            bruteforce=BruteforceState(
                charset=charset,
                min_length=min_length,
                max_length=max_length,
                current_length=min_length,
                position=0,
            ),
        )
    else:
        if resume_state.attack != "bruteforce":
            eprint("Resume file attack type differs. Starting new bruteforce session.")
            resume_state = ResumeState(
                version=1,
                hash=target_hash,
                algo=algo,
                attack="bruteforce",
                created_at=time.time(),
                updated_at=time.time(),
                attempts=0,
                progress_total=total,
                wordlist=None,
                bruteforce=BruteforceState(
                    charset=charset,
                    min_length=min_length,
                    max_length=max_length,
                    current_length=min_length,
                    position=0,
                ),
            )
        else:
            # If charsets or lengths differ, reset
            bf = resume_state.bruteforce
            if not bf or bf.charset != charset or bf.min_length != min_length or bf.max_length != max_length:
                resume_state.bruteforce = BruteforceState(
                    charset=charset,
                    min_length=min_length,
                    max_length=max_length,
                    current_length=min_length,
                    position=0,
                )
                resume_state.attempts = 0
                resume_state.progress_total = total

    tracker = ProgressTracker(total=resume_state.progress_total, interval=progress_interval, quiet=quiet)
    tracker.attempts = resume_state.attempts

    start_length = resume_state.bruteforce.current_length if resume_state.bruteforce else min_length
    start_position = resume_state.bruteforce.position if resume_state.bruteforce else 0

    interrupted = False

    def handle_sigint(sig, frame):
        nonlocal interrupted
        interrupted = True
        eprint("\nInterrupted by user. Saving state...")

    old_handler = signal.signal(signal.SIGINT, handle_sigint)
    last_state_save = time.time()

    found_plain = None
    try:
        for candidate, length, pos in generate_bruteforce_candidates(
            charset=charset,
            min_length=min_length,
            max_length=max_length,
            start_length=start_length,
            start_position=start_position,
        ):
            if interrupted:
                break
            tracker.increment()
            if hash_candidate(candidate, algo, target_hash):
                found_plain = candidate
                resume_state.found = True
                resume_state.found_plain = candidate
                resume_state.attempts = tracker.attempts
                if resume_state.bruteforce:
                    resume_state.bruteforce.current_length = length
                    resume_state.bruteforce.position = pos + 1  # next position (after success)
                if resume_file:
                    resume_state.save(resume_file)
                break
            # progress display
            tracker.maybe_print(prefix="[bruteforce] ")
            # periodic save
            now = time.time()
            if resume_file and (now - last_state_save) >= state_interval:
                if resume_state.bruteforce:
                    resume_state.bruteforce.current_length = length
                    resume_state.bruteforce.position = pos + 1
                resume_state.attempts = tracker.attempts
                resume_state.progress_total = total
                resume_state.save(resume_file)
                last_state_save = now
    finally:
        signal.signal(signal.SIGINT, old_handler)

    if resume_file:
        # save final
        if resume_state.bruteforce:
            # keep last known position/current_length
            resume_state.bruteforce.current_length = resume_state.bruteforce.current_length
            resume_state.bruteforce.position = resume_state.bruteforce.position
        resume_state.attempts = tracker.attempts
        resume_state.progress_total = total
        resume_state.save(resume_file)

    return (found_plain is not None), found_plain, resume_state


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hash Cracker Suite - Multi-algorithm hash cracking tool with wordlist and brute force attacks.",
        epilog="Warning: Authorized testing only. Ensure you have explicit permission to test targets.",
    )
    parser.add_argument("--hash", "-H", dest="hash_str", help="Target hash string to crack.")
    parser.add_argument("--algo", "-a", dest="algo", choices=SUPPORTED_ALGOS, help="Hash algorithm. If omitted, auto-detect.")
    parser.add_argument("--attack", "-t", dest="attack", choices=["wordlist", "bruteforce"], default="wordlist", help="Attack mode.")

    # Wordlist options
    parser.add_argument("--wordlist", "-w", dest="wordlist", help="Path to wordlist file (for wordlist attack).")

    # Brute force options
    parser.add_argument("--charset", dest="charset", help="Custom character set string (e.g., abc123!@).")
    parser.add_argument("--lower", action="store_true", help="Include lowercase letters in charset.")
    parser.add_argument("--upper", action="store_true", help="Include uppercase letters in charset.")
    parser.add_argument("--digits", action="store_true", help="Include digits in charset.")
    parser.add_argument("--symbols", action="store_true", help="Include symbols in charset.")
    parser.add_argument("--min-length", type=int, default=1, help="Minimum length for brute force.")
    parser.add_argument("--max-length", type=int, default=6, help="Maximum length for brute force.")

    # Progress/resume options
    parser.add_argument("--progress-interval", type=float, default=1.0, help="Seconds between progress updates.")
    parser.add_argument("--resume", action="store_true", help="Resume from a saved state file.")
    parser.add_argument("--resume-file", default="hash_cracker_resume.json", help="Path to resume state file.")
    parser.add_argument("--state-interval", type=float, default=2.0, help="Seconds between saving state to resume file.")
    parser.add_argument("--quiet", "-q", action="store_true", help="Reduce output; minimal progress messages.")

    parser.add_argument("--detect", action="store_true", help="Only detect and print the hash algorithm, then exit.")
    parser.add_argument("--version", action="version", version="Hash Cracker Suite 1.0")

    return parser.parse_args(argv)


def build_charset(args: argparse.Namespace) -> str:
    charset = ""
    if args.charset:
        charset += args.charset
    if args.lower:
        charset += "abcdefghijklmnopqrstuvwxyz"
    if args.upper:
        charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if args.digits:
        charset += "0123456789"
    if args.symbols:
        charset += "!@#$%^&*()_-+=[]{}|\\:;\"'<>,.?/`~"
    return sanitize_charset(charset)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)

    eprint("Ethical warning: Use this tool ONLY for authorized security testing. Unauthorized use may be illegal.")
    # Validate hash
    if not args.hash_str and not args.resume:
        eprint("Error: --hash is required unless using --resume to load from a saved state.")
        return 2

    resume_state: Optional[ResumeState] = None
    if args.resume:
        if not os.path.isfile(args.resume_file):
            eprint(f"Resume file not found: {args.resume_file}")
            return 2
        try:
            resume_state = ResumeState.from_file(args.resume_file)
        except Exception as ex:
            eprint(f"Failed to load resume file: {ex}")
            return 2
        # If user did not provide hash, use from state
        if not args.hash_str:
            args.hash_str = resume_state.hash
        # If user did not provide algo, use from state
        if not args.algo and resume_state.algo:
            args.algo = resume_state.algo
        # If user did not provide attack, use from state
        if args.attack is None and resume_state.attack:
            args.attack = resume_state.attack

    # Detect algorithm if not provided
    algo = args.algo
    if not algo:
        detected = detect_hash_algorithm(args.hash_str)
        if not detected:
            eprint("Error: Unable to detect hash algorithm. Provide --algo explicitly or check the hash format.")
            return 2
        algo = detected
        eprint(f"Detected algorithm: {algo}")
    else:
        # Validate hash format if possible
        detected = detect_hash_algorithm(args.hash_str)
        if detected and detected != algo:
            eprint(f"Warning: Provided algo '{algo}' differs from detected '{detected}'. Proceeding with '{algo}'.")

    # Handle --detect only
    if args.detect:
        print(algo)
        return 0

    # Route to attack
    start_time = time.time()
    try:
        if args.attack == "wordlist":
            if args.resume and resume_state and resume_state.attack == "wordlist" and resume_state.wordlist:
                wordlist_path = resume_state.wordlist.path or (args.wordlist or "")
            else:
                wordlist_path = args.wordlist or ""
            if not wordlist_path:
                eprint("Error: --wordlist is required for wordlist attack (unless resuming with a saved wordlist path).")
                return 2
            eprint(f"Starting wordlist attack using {wordlist_path} with {algo}...")
            success, plain, resume_state = crack_wordlist(
                target_hash=args.hash_str,
                algo=algo,
                wordlist_path=wordlist_path,
                progress_interval=args.progress_interval,
                resume_state=resume_state if args.resume else None,
                resume_file=args.resume_file,
                quiet=args.quiet,
                state_interval=args.state_interval,
            )
        else:
            charset = build_charset(args)
            if not charset:
                eprint("Error: Empty charset for bruteforce. Use --charset or flags like --lower --upper --digits --symbols.")
                return 2
            if args.min_length <= 0 or args.max_length <= 0 or args.min_length > args.max_length:
                eprint("Error: Invalid length range. Ensure 0 < --min-length <= --max-length.")
                return 2
            eprint(f"Starting brute force attack with charset size {len(charset)}, length {args.min_length}-{args.max_length}, algo {algo}...")
            total = bruteforce_total(charset, args.min_length, args.max_length)
            if not args.quiet:
                eprint(f"Total keyspace: {total}")
            success, plain, resume_state = crack_bruteforce(
                target_hash=args.hash_str,
                algo=algo,
                charset=charset,
                min_length=args.min_length,
                max_length=args.max_length,
                progress_interval=args.progress_interval,
                resume_state=resume_state if args.resume else None,
                resume_file=args.resume_file,
                quiet=args.quiet,
                state_interval=args.state_interval,
            )
    except FileNotFoundError as fnf:
        eprint(f"Error: {fnf}")
        return 2
    except ValueError as ve:
        eprint(f"Error: {ve}")
        return 2
    except RuntimeError as re_err:
        eprint(f"Error: {re_err}")
        return 2
    except KeyboardInterrupt:
        eprint("\nInterrupted by user.")
        return 130
    except Exception as ex:
        eprint(f"Unexpected error: {ex}")
        return 2

    duration = time.time() - start_time
    if success:
        print(f"Cracked: {plain}")
        eprint(f"Success in {duration:.2f}s")
        return 0
    else:
        eprint(f"Not cracked after {duration:.2f}s. Consider expanding wordlists, charset, or length range.")
        return 1


class HashCracker:
    """
    Hash Cracker Suite library interface.

    Warning: Authorized testing only. Ensure you have explicit permission.
    """
    DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "rockyou.txt")

    def __init__(self, progress_interval: float = 1.0, state_interval: float = 2.0, quiet: bool = True):
        self.progress_interval = progress_interval
        self.state_interval = state_interval
        self.quiet = quiet

    @staticmethod
    def detect(hash_str: str) -> Optional[str]:
        return detect_hash_algorithm(hash_str)

    @staticmethod
    def hash_candidate(candidate: str, algo: str, target_hash: str) -> bool:
        return hash_candidate(candidate, algo, target_hash)

    def crack_with_wordlist(
        self,
        hash_str: str,
        algo: Optional[str] = None,
        wordlist_path: Optional[str] = None,
        resume: bool = False,
        resume_file: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        if not hash_str:
            raise ValueError("hash_str is required.")
        if not algo:
            algo = detect_hash_algorithm(hash_str)
            if not algo:
                raise ValueError("Unable to detect hash algorithm from hash_str.")
        if not wordlist_path:
            # fallback to default sample if exists
            if os.path.isfile(self.DEFAULT_WORDLIST):
                wordlist_path = self.DEFAULT_WORDLIST
            else:
                raise ValueError("wordlist_path is required for wordlist cracking.")
        resume_state = None
        if resume and resume_file and os.path.isfile(resume_file):
            try:
                resume_state = ResumeState.from_file(resume_file)
            except Exception:
                resume_state = None
        success, plain, _ = crack_wordlist(
            target_hash=hash_str,
            algo=algo,
            wordlist_path=wordlist_path,
            progress_interval=self.progress_interval,
            resume_state=resume_state if resume else None,
            resume_file=resume_file,
            quiet=self.quiet,
            state_interval=self.state_interval,
        )
        return success, plain

    def crack_with_bruteforce(
        self,
        hash_str: str,
        algo: Optional[str] = None,
        charset: Optional[str] = None,
        lower: bool = False,
        upper: bool = False,
        digits: bool = False,
        symbols: bool = False,
        min_length: int = 1,
        max_length: int = 6,
        resume: bool = False,
        resume_file: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        if not hash_str:
            raise ValueError("hash_str is required.")
        if not algo:
            algo = detect_hash_algorithm(hash_str)
            if not algo:
                raise ValueError("Unable to detect hash algorithm from hash_str.")
        # Build charset
        ch = charset or ""
        if lower:
            ch += "abcdefghijklmnopqrstuvwxyz"
        if upper:
            ch += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if digits:
            ch += "0123456789"
        if symbols:
            ch += "!@#$%^&*()_-+=[]{}|\\:;\"'<>,.?/`~"
        ch = sanitize_charset(ch)
        if not ch:
            raise ValueError("Empty charset. Provide charset or set flags lower/upper/digits/symbols.")
        if min_length <= 0 or max_length <= 0 or min_length > max_length:
            raise ValueError("Invalid length range. Ensure 0 < min_length <= max_length.")
        resume_state = None
        if resume and resume_file and os.path.isfile(resume_file):
            try:
                resume_state = ResumeState.from_file(resume_file)
            except Exception:
                resume_state = None
        success, plain, _ = crack_bruteforce(
            target_hash=hash_str,
            algo=algo,
            charset=ch,
            min_length=min_length,
            max_length=max_length,
            progress_interval=self.progress_interval,
            resume_state=resume_state if resume else None,
            resume_file=resume_file,
            quiet=self.quiet,
            state_interval=self.state_interval,
        )
        return success, plain


if __name__ == "__main__":
    sys.exit(main())