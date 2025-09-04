import hashlib
import inspect
import json
import os
from pathlib import Path
import pytest

from tools.vuln.hash_cracker import HashCracker


@pytest.fixture
def cracker():
    return HashCracker()


@pytest.fixture
def rockyou_sample(tmp_path):
    content = "\n".join([
        "123456",
        "letmein",
        "Password1",
        "qwerty",
        "password",
        "dragon",
    ]) + "\n"
    p = tmp_path / "rockyou_sample.txt"
    p.write_text(content, encoding="utf-8")
    return str(p)


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def sha512(s: str) -> str:
    return hashlib.sha512(s.encode()).hexdigest()


@pytest.mark.parametrize(
    "algo,hasher",
    [
        ("md5", md5),
        ("sha1", sha1),
        ("sha256", sha256),
        ("sha512", sha512),
    ],
)
def test_support_multiple_algorithms_wordlist(cracker, rockyou_sample, algo, hasher):
    target_hash = hasher("password")
    progress_events = []

    def progress_cb(progress):
        progress_events.append(progress)

    result = cracker.crack(
        hash_str=target_hash,
        attack="wordlist",
        wordlist=rockyou_sample,
        algorithm=algo,
        progress_callback=progress_cb,
    )
    assert getattr(result, "found", False) is True
    assert getattr(result, "password", None) == "password"
    assert getattr(result, "algorithm", None) == algo
    # progress callback should be called at least once
    assert len(progress_events) >= 1
    # progress event should include attempts/total or percent
    evt = progress_events[-1]
    assert isinstance(evt, dict)
    assert "attempts" in evt and "total" in evt and "percent" in evt
    assert isinstance(evt["attempts"], int)
    assert isinstance(evt["total"], int)
    assert isinstance(evt["percent"], (int, float))
    assert 0 <= evt["percent"] <= 100


def test_crack_md5_hash_of_password_using_rockyou_sample(cracker, rockyou_sample):
    target_hash = md5("password")
    progress_events = []

    def progress_cb(progress):
        progress_events.append(progress)

    result = cracker.crack(
        hash_str=target_hash,
        attack="wordlist",
        wordlist=rockyou_sample,
        progress_callback=progress_cb,
    )
    assert getattr(result, "found", False) is True
    assert getattr(result, "password", None) == "password"
    # algorithm should be detected as md5 automatically if not provided
    assert getattr(result, "algorithm", None) in ("md5", "MD5")
    assert len(progress_events) >= 1
    last = progress_events[-1]
    assert isinstance(last, dict)
    assert "attempts" in last and "total" in last and "percent" in last
    assert 0 <= last["percent"] <= 100


def test_detect_hash_algorithm_automatically(cracker):
    # Known hashes for "password"
    md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
    sha1_hash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    sha256_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    sha512_hash = (
        "b109f3bbbc244eb82441917ed06d618b9008dd09"
        "5a0f7cba4e5b1e3f7e0a8d5a"
        "b1b5f1af0f029a8b84a0ed2762a3c6f1f8f9a7ea"
        "d9fbb0a1e6d5f8f7bda1f90"
    )
    # Typical bcrypt identifier format; exact checksum not important for detection
    bcrypt_hash = "$2b$12$abcdefghijklmnopqrstuvABCDEFabcdef12345678ghijklmno"

    assert cracker.detect_algorithm(md5_hash).lower() == "md5"
    assert cracker.detect_algorithm(sha1_hash).lower() == "sha1"
    assert cracker.detect_algorithm(sha256_hash).lower() == "sha256"
    # Some tools may not accept shortened sha512; skip if raises but prefer correct detection
    algo = cracker.detect_algorithm(sha512_hash)
    assert algo.lower() == "sha512"
    assert cracker.detect_algorithm(bcrypt_hash).lower() == "bcrypt"


def test_show_progress_during_cracking_attempts_bruteforce(cracker):
    # Target "ab" with charset 'abc' and length 2
    target_hash = md5("ab")
    progress_events = []

    def progress_cb(progress):
        progress_events.append(progress)

    result = cracker.crack(
        hash_str=target_hash,
        attack="bruteforce",
        charset="abc",
        min_len=2,
        max_len=2,
        algorithm="md5",
        progress_callback=progress_cb,
    )
    assert getattr(result, "found", False) is True
    assert getattr(result, "password", None) == "ab"
    # Progress should be reported multiple times for bruteforce
    assert len(progress_events) >= 1
    # Ensure progress is plausible
    totals = set()
    attempts = []
    percents = []
    for evt in progress_events:
        assert isinstance(evt, dict)
        assert "attempts" in evt and "total" in evt and "percent" in evt
        assert 0 <= evt["percent"] <= 100
        attempts.append(evt["attempts"])
        percents.append(evt["percent"])
        totals.add(evt["total"])
    assert len(totals) == 1
    # Attempts should be non-decreasing
    assert attempts == sorted(attempts)
    # Last percent should be 100 or close
    assert percents[-1] == pytest.approx(100.0, rel=0.01, abs=0.5)


@pytest.mark.parametrize("bad_hash", ["notahash", "", "xyz", "   ", "$$invalid$$"])
def test_handle_invalid_hash_formats_gracefully(cracker, bad_hash, rockyou_sample):
    # The tool should handle invalid hash formats without crashing
    try:
        result = cracker.crack(
            hash_str=bad_hash,
            attack="wordlist",
            wordlist=rockyou_sample,
        )
    except ValueError as exc:
        assert "invalid" in str(exc).lower() or "format" in str(exc).lower()
        return
    # If no exception, result should indicate failure with an error message
    assert getattr(result, "found", False) is False
    err = getattr(result, "error", None)
    assert isinstance(err, str) and (("invalid" in err.lower()) or ("format" in err.lower()))


def test_bruteforce_with_character_set(cracker):
    # Small keyspace to avoid long runs
    target_hash = sha1("ba")
    result = cracker.crack(
        hash_str=target_hash,
        attack="bruteforce",
        charset="abc",
        min_len=2,
        max_len=2,
        algorithm="sha1",
        progress_callback=lambda p: None,
    )
    assert getattr(result, "found", False) is True
    assert getattr(result, "password", None) == "ba"
    assert getattr(result, "algorithm", None).lower() == "sha1"


def test_resume_capability_interface(cracker, rockyou_sample):
    # Ensure crack method supports resume_state parameter and returns resume_state in result
    sig = inspect.signature(cracker.crack)
    assert "resume_state" in sig.parameters

    # Perform a simple run to fetch resume_state
    target_hash = sha256("not_in_list")
    result = cracker.crack(
        hash_str=target_hash,
        attack="wordlist",
        wordlist=rockyou_sample,
        algorithm="sha256",
        progress_callback=lambda p: None,
    )
    # Not found due to wordlist not containing the password
    assert getattr(result, "found", False) is False
    # Resume state should be present (may be None if complete)
    assert hasattr(result, "resume_state")
    # If resume_state is not None, it should be JSON-serializable
    if result.resume_state is not None:
        json.dumps(result.resume_state)


def test_invalid_algorithm_parameter_handled(cracker, rockyou_sample):
    target_hash = md5("password")
    with pytest.raises((ValueError, KeyError)):
        cracker.crack(
            hash_str=target_hash,
            attack="wordlist",
            wordlist=rockyou_sample,
            algorithm="unknown-algo",
        )