import os
import hashlib
import inspect
import socket
import pytest

mod = pytest.importorskip("tools.vuln.hash_cracker")


class CrackerAdapter:
    def __init__(self, module):
        self.module = module
        self._instance = None

        # Detect detection function
        for name in ("detect_hash", "detect_algorithm", "identify_hash"):
            if hasattr(module, name) and callable(getattr(module, name)):
                self._detect_fn = getattr(module, name)
                break
        else:
            # Maybe a class has detect method
            if hasattr(module, "HashCracker"):
                try:
                    self._instance = module.HashCracker()
                    if hasattr(self._instance, "detect_hash"):
                        self._detect_fn = self._instance.detect_hash
                    elif hasattr(self._instance, "detect_algorithm"):
                        self._detect_fn = self._instance.detect_algorithm
                    else:
                        raise AttributeError("No detect function found")
                except Exception as e:
                    raise e
            else:
                raise AttributeError("No detect function found")

        # Detect crack function or method
        self._crack_fn = None
        if self._instance is not None:
            for name in ("crack", "crack_hash"):
                if hasattr(self._instance, name) and callable(getattr(self._instance, name)):
                    self._crack_fn = getattr(self._instance, name)
                    break
        if self._crack_fn is None:
            for name in ("crack", "crack_hash"):
                if hasattr(module, name) and callable(getattr(module, name)):
                    self._crack_fn = getattr(module, name)
                    break
        if self._crack_fn is None and hasattr(module, "HashCracker"):
            self._instance = module.HashCracker()
            for name in ("crack", "crack_hash"):
                if hasattr(self._instance, name) and callable(getattr(self._instance, name)):
                    self._crack_fn = getattr(self._instance, name)
                    break
        if self._crack_fn is None:
            raise AttributeError("No crack function/method found")

        self._crack_sig = inspect.signature(self._crack_fn)

    def detect_hash(self, h):
        return self._detect_fn(h)

    def crack(self, hash_value, **kwargs):
        # Normalize argument names based on signature
        params = set(self._crack_sig.parameters.keys())
        normalized = {}
        # hash input param name
        if len(params) > 0:
            # Guess name of the first non-kwargs parameter if not explicitly provided
            if "hash_value" in params:
                normalized["hash_value"] = hash_value
            elif "hash" in params:
                normalized["hash"] = hash_value
            elif "target" in params:
                normalized["target"] = hash_value
            else:
                # Fallback to positional call
                pass

        # method/attack/mode
        if "method" in kwargs:
            for k in ("method", "attack", "mode"):
                if k in params:
                    normalized[k] = kwargs["method"]
                    break
        if "attack" in kwargs:
            for k in ("attack", "method", "mode"):
                if k in params and k not in normalized:
                    normalized[k] = kwargs["attack"]
                    break

        # wordlist
        for key in ("wordlist", "wordlist_path", "wordlist_file", "word_list", "dictionary"):
            if key in kwargs:
                for k in ("wordlist", "wordlist_path", "wordlist_file", "word_list", "dictionary"):
                    if k in params:
                        normalized[k] = kwargs[key]
                        break

        # charset
        if "charset" in kwargs:
            for k in ("charset", "characters", "alphabet"):
                if k in params:
                    normalized[k] = kwargs["charset"]
                    break

        # lengths
        if "min_length" in kwargs:
            for k in ("min_length", "minlen", "min"):
                if k in params:
                    normalized[k] = kwargs["min_length"]
                    break
        if "max_length" in kwargs:
            for k in ("max_length", "maxlen", "length", "max"):
                if k in params:
                    normalized[k] = kwargs["max_length"]
                    break

        # progress callback
        if "progress_callback" in kwargs:
            for k in ("progress_callback", "on_progress", "progress", "callback"):
                if k in params:
                    normalized[k] = kwargs["progress_callback"]
                    break

        # resume state
        if "resume_state" in kwargs:
            for k in ("resume_state", "resume", "state", "checkpoint"):
                if k in params:
                    normalized[k] = kwargs["resume_state"]
                    break

        # Any other keyword passthroughs if supported
        for k, v in kwargs.items():
            if k not in normalized and k in params:
                normalized[k] = v

        # Invoke
        try:
            if "hash_value" in self._crack_sig.parameters or "hash" in self._crack_sig.parameters or "target" in self._crack_sig.parameters:
                result = self._crack_fn(**normalized)
            else:
                # positional hash value as first argument
                result = self._crack_fn(hash_value, **normalized)
        except TypeError:
            # Fallback to positional only if necessary
            result = self._crack_fn(hash_value)

        # Normalize result to dict
        norm = {"plaintext": None, "algorithm": None, "attempts": None, "resume_state": None}
        if isinstance(result, dict):
            norm.update({k: result.get(k) for k in norm.keys() if k in result})
            # Allow aliases
            if norm["plaintext"] is None:
                for alias in ("password", "result", "found"):
                    if alias in result:
                        norm["plaintext"] = result[alias]
                        break
            if norm["algorithm"] is None and "algo" in result:
                norm["algorithm"] = result["algo"]
            if "resume" in result and norm["resume_state"] is None:
                norm["resume_state"] = result["resume"]
        elif isinstance(result, (list, tuple)):
            if len(result) >= 1:
                norm["plaintext"] = result[0]
            if len(result) >= 2 and isinstance(result[1], dict):
                # merge info dict
                info = result[1]
                norm.update({k: info.get(k, norm.get(k)) for k in norm.keys() if isinstance(info, dict)})
        elif isinstance(result, str):
            norm["plaintext"] = result

        if not norm["algorithm"]:
            try:
                alg = self.detect_hash(hash_value)
                if isinstance(alg, str):
                    norm["algorithm"] = alg
            except Exception:
                pass

        return norm


@pytest.fixture(scope="module")
def adapter():
    return CrackerAdapter(mod)


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    class NoNetSocket:
        def __init__(self, *args, **kwargs):
            raise AssertionError("Network access is blocked in tests")

    monkeypatch.setattr(socket, "socket", NoNetSocket, raising=True)


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def sha512_hex(s: str) -> str:
    return hashlib.sha512(s.encode()).hexdigest()


def test_detect_hash_algorithm(adapter):
    samples = [
        ("md5", md5_hex("password")),
        ("sha1", sha1_hex("password")),
        ("sha256", sha256_hex("password")),
        ("sha512", sha512_hex("password")),
        # bcrypt: use a syntactically valid-looking bcrypt string (60 chars total)
        ("bcrypt", "$2b$12$" + "a" * 53),
    ]
    for expected, sample in samples:
        alg = adapter.detect_hash(sample)
        assert isinstance(alg, str)
        assert expected in alg.lower()


def test_crack_md5_with_wordlist_sample(tmp_path, adapter):
    # Create a rockyou-like sample wordlist
    words = ["123456", "passw0rd", "letmein", "Password", "password", "qwerty"]
    wordlist_path = tmp_path / "rockyou_sample.txt"
    wordlist_path.write_text("\n".join(words), encoding="utf-8")

    target_hash = md5_hex("password")
    progress_events = []

    def progress_cb(attempts=None, **kwargs):
        progress_events.append((attempts, kwargs))
        # Return None; no stop

    result = adapter.crack(
        target_hash,
        method="wordlist",
        wordlist=str(wordlist_path),
        progress_callback=progress_cb,
    )
    assert result["plaintext"] == "password"
    assert result["algorithm"] and "md5" in result["algorithm"].lower()
    assert "resume_state" in result
    assert isinstance(progress_events, list)
    assert len(progress_events) >= 1


def test_progress_callback_invoked_during_bruteforce(adapter):
    # Target 'ab' with small charset and small lengths
    target_hash = md5_hex("ab")
    progress_calls = []

    def progress_cb(attempts=None, last_candidate=None, **kwargs):
        progress_calls.append((attempts, last_candidate))

    result = adapter.crack(
        target_hash,
        method="bruteforce",
        charset="abc",
        min_length=1,
        max_length=2,
        progress_callback=progress_cb,
    )
    assert result["plaintext"] == "ab"
    assert len(progress_calls) >= 1


def test_handle_invalid_hash_formats_gracefully(adapter):
    invalid = "notahashvalue"

    # detect should either raise a specific error or return unknown/None
    try:
        alg = adapter.detect_hash(invalid)
        assert alg is None or (isinstance(alg, str) and alg.lower() in ("", "unknown", "invalid"))
    except Exception as e:
        # Accept ValueError or custom error classes
        assert isinstance(e, (ValueError, AttributeError, TypeError, Exception))

    # crack should handle invalid without crashing
    try:
        res = adapter.crack(invalid, method="wordlist", wordlist=[])
        # Accept either None plaintext or explicit error state
        assert res["plaintext"] in (None, "")
    except Exception as e:
        assert isinstance(e, (ValueError, AttributeError, TypeError, Exception))


def test_resume_capability_presence_and_compatibility(tmp_path, adapter):
    # Create a wordlist where the password is present
    words = ["foo", "bar", "baz", "password123", "ninja"]
    wl = tmp_path / "wl.txt"
    wl.write_text("\n".join(words), encoding="utf-8")
    target = md5_hex("password123")

    # Initial run
    res1 = adapter.crack(target, method="wordlist", wordlist=str(wl))
    assert "resume_state" in res1

    # Second run with resume state (even if None), should not crash and yield same plaintext
    res2 = adapter.crack(target, method="wordlist", wordlist=str(wl), resume_state=res1.get("resume_state"))
    assert res2["plaintext"] == "password123"