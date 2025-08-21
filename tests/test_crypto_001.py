import importlib
import inspect
import os
from pathlib import Path
import pytest


def import_module():
    return importlib.import_module("tools.crypto.encryption_suite")


class CryptoBridge:
    def __init__(self, mod):
        self.mod = mod
        self.obj = getattr(mod, "EncryptionSuite", None)
        if inspect.isclass(self.obj):
            try:
                self.obj = self.obj()
            except Exception:
                # Fall back to module-level if instantiation fails
                self.obj = mod
        else:
            self.obj = mod

        self.encrypt_file = self._find_callable(
            ["encrypt_file", "file_encrypt", "encrypt_path", "encrypt_file_with_key", "encrypt_file_key"]
        )
        self.decrypt_file = self._find_callable(
            ["decrypt_file", "file_decrypt", "decrypt_path", "decrypt_file_with_key", "decrypt_file_key"]
        )
        self.secure_random = self._find_callable(
            ["secure_random_bytes", "get_secure_random", "random_bytes", "generate_secure_key", "gen_secure_bytes"]
        )
        self.derive_key = self._find_callable(
            ["derive_key_from_password", "pbkdf2", "pbkdf2_derive", "password_to_key", "derive_key", "pbkdf2_hmac"]
        )
        self.rsa_keygen = self._find_callable(
            ["rsa_generate_keypair", "generate_rsa_keypair", "generate_rsa_keys", "rsa_keygen", "generate_keypair_rsa"]
        )
        self.rsa_encrypt = self._find_callable(
            ["rsa_encrypt", "encrypt_rsa", "asymmetric_encrypt"]
        )
        self.rsa_decrypt = self._find_callable(
            ["rsa_decrypt", "decrypt_rsa", "asymmetric_decrypt"]
        )

    def _find_callable(self, names):
        for n in names:
            f = getattr(self.obj, n, None)
            if callable(f):
                return f
        return None

    @staticmethod
    def _filter_kwargs(func, kwargs):
        try:
            sig = inspect.signature(func)
        except (TypeError, ValueError):
            return kwargs
        params = sig.parameters
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
            return kwargs
        return {k: v for k, v in kwargs.items() if k in params}

    def call_with_paths(self, func, src: Path, dst: Path, extra_kwargs=None):
        if func is None:
            pytest.skip("Required file operation not implemented")
        extra_kwargs = extra_kwargs or {}
        sig = None
        try:
            sig = inspect.signature(func)
        except (TypeError, ValueError):
            pass

        # Build keyword mapping for src/dst by name if possible
        in_names = [
            "input_path", "in_path", "src", "source", "input_file", "infile",
            "path_in", "plaintext_path", "plain_path", "filename_in"
        ]
        out_names = [
            "output_path", "out_path", "dst", "destination", "output_file", "outfile",
            "path_out", "ciphertext_path", "cipher_path", "filename_out"
        ]
        kwargs = dict(extra_kwargs)
        used_kw = False
        if sig is not None:
            params = sig.parameters
            for n in in_names:
                if n in params:
                    kwargs[n] = str(src)
                    used_kw = True
                    break
            for n in out_names:
                if n in params:
                    kwargs[n] = str(dst)
                    used_kw = True
                    break

        kwargs = self._filter_kwargs(func, kwargs)

        if used_kw:
            return func(**kwargs)
        else:
            # Try positional call
            try:
                return func(str(src), str(dst), **kwargs)
            except TypeError:
                # Try only keywords failed, so raise
                return func(**kwargs)


@pytest.fixture(scope="module")
def bridge():
    mod = import_module()
    return CryptoBridge(mod)


@pytest.fixture
def tmp_plaintext(tmp_path):
    data = (
        b"The quick brown fox jumps over the lazy dog. "
        b"This is a test plaintext with multiple lines.\n"
        b"1234567890\x00\x01\x02\x03\xff"
    )
    p = tmp_path / "plain.txt"
    p.write_bytes(data)
    return p


def random_key(bridge: CryptoBridge, n=32):
    if bridge.secure_random is None:
        return os.urandom(n)
    kwargs = {}
    sig = None
    try:
        sig = inspect.signature(bridge.secure_random)
    except (TypeError, ValueError):
        sig = None
    if sig is not None:
        params = sig.parameters
        if "n" in params:
            return bridge.secure_random(n=n)
        if "length" in params:
            return bridge.secure_random(length=n)
        if len([p for p in params.values() if p.default is inspect._empty and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]) >= 1:
            return bridge.secure_random(n)
    return bridge.secure_random()


def supports_mode(bridge: CryptoBridge):
    if bridge.encrypt_file is None:
        return False
    try:
        sig = inspect.signature(bridge.encrypt_file)
    except (TypeError, ValueError):
        return False
    return "mode" in sig.parameters


# Acceptance: Encrypt and decrypt a test file successfully
def test_encrypt_decrypt_file_success(bridge: CryptoBridge, tmp_plaintext, tmp_path):
    if bridge.encrypt_file is None or bridge.decrypt_file is None:
        pytest.skip("File encryption/decryption functions not implemented")

    key = random_key(bridge, 32)
    enc = tmp_path / "enc.bin"
    dec = tmp_path / "dec.txt"

    # Encrypt
    bridge.call_with_paths(bridge.encrypt_file, tmp_plaintext, enc, extra_kwargs={"key": key})
    assert enc.exists() and enc.stat().st_size > 0
    assert enc.read_bytes() != tmp_plaintext.read_bytes()

    # Decrypt
    bridge.call_with_paths(bridge.decrypt_file, enc, dec, extra_kwargs={"key": key})
    assert dec.exists()
    assert dec.read_bytes() == tmp_plaintext.read_bytes()


# Acceptance: Verify file integrity after encryption/decryption
def test_file_integrity_tamper_detection(bridge: CryptoBridge, tmp_plaintext, tmp_path):
    if bridge.encrypt_file is None or bridge.decrypt_file is None:
        pytest.skip("File encryption/decryption functions not implemented")

    key = random_key(bridge, 32)
    enc = tmp_path / "enc_t.bin"
    dec = tmp_path / "dec_t.txt"
    bridge.call_with_paths(bridge.encrypt_file, tmp_plaintext, enc, extra_kwargs={"key": key})

    # Tamper with encrypted file
    data = bytearray(enc.read_bytes())
    if not data:
        pytest.skip("Encrypted file is empty; cannot test tampering")
    idx = len(data) // 2
    data[idx] ^= 0x01
    enc.write_bytes(bytes(data))

    # Decryption should fail due to integrity check
    with pytest.raises(Exception):
        bridge.call_with_paths(bridge.decrypt_file, enc, dec, extra_kwargs={"key": key})


# Acceptance: Generate secure RSA key pairs
def test_generate_secure_rsa_key_pairs(bridge: CryptoBridge):
    if bridge.rsa_keygen is None:
        pytest.skip("RSA key generation not implemented")

    # Try common key_size parameter names
    kwargs = {}
    try:
        sig = inspect.signature(bridge.rsa_keygen)
    except (TypeError, ValueError):
        sig = None
    if sig is not None:
        params = sig.parameters
        if "key_size" in params:
            kwargs["key_size"] = 2048
        elif "bits" in params:
            kwargs["bits"] = 2048

    keys = bridge.rsa_keygen(**kwargs) if kwargs else bridge.rsa_keygen()
    if isinstance(keys, dict):
        priv = keys.get("private_key") or keys.get("private") or keys.get("priv") or keys.get("private_pem")
        pub = keys.get("public_key") or keys.get("public") or keys.get("pub") or keys.get("public_pem")
    elif isinstance(keys, (list, tuple)) and len(keys) >= 2:
        priv, pub = keys[0], keys[1]
    else:
        # Single object keypair; try to extract attributes
        priv = getattr(keys, "private_key", None) or getattr(keys, "private", None)
        pub = getattr(keys, "public_key", None) or getattr(keys, "public", None)

    assert priv is not None and pub is not None
    # PEM-like sanity if strings/bytes
    if isinstance(priv, (bytes, str)):
        s = priv.decode() if isinstance(priv, bytes) else priv
        assert "PRIVATE KEY" in s
    if isinstance(pub, (bytes, str)):
        s = pub.decode() if isinstance(pub, bytes) else pub
        assert "PUBLIC KEY" in s


def try_rsa_encrypt_decrypt(bridge: CryptoBridge, message: bytes):
    if bridge.rsa_encrypt is None or bridge.rsa_decrypt is None or bridge.rsa_keygen is None:
        pytest.skip("RSA encrypt/decrypt operations not implemented")

    keys = bridge.rsa_keygen(key_size=2048) if "key_size" in getattr(inspect.signature(bridge.rsa_keygen), "parameters", {}) else bridge.rsa_keygen()
    if isinstance(keys, dict):
        priv = keys.get("private_key") or keys.get("private") or keys.get("priv") or keys.get("private_pem")
        pub = keys.get("public_key") or keys.get("public") or keys.get("pub") or keys.get("public_pem")
    else:
        priv, pub = (keys[0], keys[1]) if isinstance(keys, (list, tuple)) else (None, None)

    assert priv is not None and pub is not None

    # encrypt
    enc_kwargs = {}
    sig_e = inspect.signature(bridge.rsa_encrypt)
    if "public_key" in sig_e.parameters:
        enc_kwargs["public_key"] = pub
    elif "key" in sig_e.parameters:
        enc_kwargs["key"] = pub
    elif "pub" in sig_e.parameters:
        enc_kwargs["pub"] = pub
    if "message" in sig_e.parameters:
        enc_kwargs["message"] = message
    elif "data" in sig_e.parameters:
        enc_kwargs["data"] = message
    else:
        # pass as positional
        ciphertext = bridge.rsa_encrypt(pub, message)
        # decrypt path
        sig_d = inspect.signature(bridge.rsa_decrypt)
        dec_kwargs = {}
        if "private_key" in sig_d.parameters:
            dec_kwargs["private_key"] = priv
        elif "key" in sig_d.parameters:
            dec_kwargs["key"] = priv
        elif "priv" in sig_d.parameters:
            dec_kwargs["priv"] = priv
        if "ciphertext" in sig_d.parameters:
            dec_kwargs["ciphertext"] = ciphertext
        elif "data" in sig_d.parameters:
            dec_kwargs["data"] = ciphertext
        else:
            plaintext = bridge.rsa_decrypt(priv, ciphertext)
            return plaintext
        plaintext = bridge.rsa_decrypt(**dec_kwargs)
        return plaintext

    ciphertext = bridge.rsa_encrypt(**enc_kwargs)

    # decrypt
    sig_d = inspect.signature(bridge.rsa_decrypt)
    dec_kwargs = {}
    if "private_key" in sig_d.parameters:
        dec_kwargs["private_key"] = priv
    elif "key" in sig_d.parameters:
        dec_kwargs["key"] = priv
    elif "priv" in sig_d.parameters:
        dec_kwargs["priv"] = priv
    if "ciphertext" in sig_d.parameters:
        dec_kwargs["ciphertext"] = ciphertext
    elif "data" in sig_d.parameters:
        dec_kwargs["data"] = ciphertext
    else:
        plaintext = bridge.rsa_decrypt(priv, ciphertext)
        return plaintext

    plaintext = bridge.rsa_decrypt(**dec_kwargs)
    return plaintext


def test_rsa_encrypt_decrypt_roundtrip(bridge: CryptoBridge):
    if bridge.rsa_encrypt is None or bridge.rsa_decrypt is None or bridge.rsa_keygen is None:
        pytest.skip("RSA operations not implemented")
    msg = b"hello asymmetric crypto"
    out = try_rsa_encrypt_decrypt(bridge, msg)
    assert out == msg


# Acceptance: Handle password-based encryption
def test_password_based_file_encryption_roundtrip(bridge: CryptoBridge, tmp_plaintext, tmp_path):
    if bridge.encrypt_file is None or bridge.decrypt_file is None:
        pytest.skip("File encryption/decryption functions not implemented")

    password = "correct horse battery staple"
    enc = tmp_path / "pw_enc.bin"
    dec = tmp_path / "pw_dec.txt"

    # Prefer direct password param if supported
    sig_e = inspect.signature(bridge.encrypt_file)
    sig_d = inspect.signature(bridge.decrypt_file)
    supports_password = "password" in sig_e.parameters and "password" in sig_d.parameters

    if supports_password:
        bridge.call_with_paths(bridge.encrypt_file, tmp_plaintext, enc, extra_kwargs={"password": password})
        bridge.call_with_paths(bridge.decrypt_file, enc, dec, extra_kwargs={"password": password})
        assert dec.read_bytes() == tmp_plaintext.read_bytes()
        # Wrong password should fail
        with pytest.raises(Exception):
            wrong = tmp_path / "wrong.txt"
            bridge.call_with_paths(bridge.decrypt_file, enc, wrong, extra_kwargs={"password": "wrong password"})
    elif bridge.derive_key is not None:
        # Derive key with a salt and use key-based file encryption
        salt1 = os.urandom(16)
        sig_kdf = inspect.signature(bridge.derive_key)
        kdf_kwargs = {"password": password} if "password" in sig_kdf.parameters else {"pwd": password}
        if "salt" in sig_kdf.parameters:
            kdf_kwargs["salt"] = salt1
        if "length" in sig_kdf.parameters:
            kdf_kwargs["length"] = 32
        elif "dklen" in sig_kdf.parameters:
            kdf_kwargs["dklen"] = 32
        key = bridge.derive_key(**kdf_kwargs)
        if isinstance(key, (tuple, list)):
            key = key[0]
        bridge.call_with_paths(bridge.encrypt_file, tmp_plaintext, enc, extra_kwargs={"key": key})
        bridge.call_with_paths(bridge.decrypt_file, enc, dec, extra_kwargs={"key": key})
        assert dec.read_bytes() == tmp_plaintext.read_bytes()

        # Wrong key derived from wrong password should fail
        kdf_kwargs_wrong = dict(kdf_kwargs)
        if "password" in kdf_kwargs_wrong:
            kdf_kwargs_wrong["password"] = "wrong password"
        elif "pwd" in kdf_kwargs_wrong:
            kdf_kwargs_wrong["pwd"] = "wrong password"
        wrong_key = bridge.derive_key(**kdf_kwargs_wrong)
        if isinstance(wrong_key, (tuple, list)):
            wrong_key = wrong_key[0]
        with pytest.raises(Exception):
            wrong_out = tmp_path / "wrong2.txt"
            bridge.call_with_paths(bridge.decrypt_file, enc, wrong_out, extra_kwargs={"key": wrong_key})
    else:
        pytest.skip("Neither direct password encryption nor PBKDF2 derivation available")


def test_pbkdf2_derivation_reproducibility_and_salt(bridge: CryptoBridge):
    if bridge.derive_key is None:
        pytest.skip("PBKDF2 not implemented")

    password = "pa$$w0rd!"
    sig_kdf = inspect.signature(bridge.derive_key)
    # Use explicit salt if supported
    if "salt" in sig_kdf.parameters:
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)
        kwargs = {"password": password} if "password" in sig_kdf.parameters else {"pwd": password}
        kwargs_len = {}
        if "length" in sig_kdf.parameters:
            kwargs_len["length"] = 32
        elif "dklen" in sig_kdf.parameters:
            kwargs_len["dklen"] = 32

        k1 = bridge.derive_key(**kwargs, salt=salt1, **kwargs_len)
        k2 = bridge.derive_key(**kwargs, salt=salt1, **kwargs_len)
        k3 = bridge.derive_key(**kwargs, salt=salt2, **kwargs_len)

        if isinstance(k1, (tuple, list)):
            k1 = k1[0]
            k2 = k2[0]
            k3 = k3[0]
        assert isinstance(k1, (bytes, bytearray))
        assert k1 == k2
        assert k1 != k3
    else:
        # Without salt parameter, ensure it at least returns bytes and consecutive keys differ
        k1 = bridge.derive_key(password=password) if "password" in sig_kdf.parameters else bridge.derive_key(pwd=password)
        k2 = bridge.derive_key(password=password) if "password" in sig_kdf.parameters else bridge.derive_key(pwd=password)
        if isinstance(k1, (tuple, list)):
            k1 = k1[0]
            k2 = k2[0]
        assert isinstance(k1, (bytes, bytearray))
        assert k1 != k2


def test_secure_random_bytes_quality(bridge: CryptoBridge):
    if bridge.secure_random is None:
        pytest.skip("Secure random key generation not implemented")
    a = random_key(bridge, 32)
    b = random_key(bridge, 32)
    assert isinstance(a, (bytes, bytearray))
    assert len(a) == 32 and len(b) == 32
    assert a != b
    assert any(x != 0 for x in a)


def test_secure_random_bytes_invalid_length(bridge: CryptoBridge):
    if bridge.secure_random is None:
        pytest.skip("Secure random key generation not implemented")
    # Negative length should raise
    with pytest.raises(Exception):
        sig = inspect.signature(bridge.secure_random)
        if "n" in sig.parameters:
            bridge.secure_random(n=-1)
        elif "length" in sig.parameters:
            bridge.secure_random(length=-1)
        else:
            bridge.secure_random(-1)


@pytest.mark.parametrize("mode", ["GCM", "CBC", "CFB", "CTR"])
def test_file_encryption_multiple_modes_if_supported(bridge: CryptoBridge, tmp_plaintext, tmp_path, mode):
    if bridge.encrypt_file is None or bridge.decrypt_file is None:
        pytest.skip("File encryption/decryption functions not implemented")

    if not supports_mode(bridge):
        pytest.skip("Encryption mode parameter not supported for file operations")

    key = random_key(bridge, 32)
    enc = tmp_path / f"enc_{mode}.bin"
    dec = tmp_path / f"dec_{mode}.txt"

    # Try encrypt with mode if supported
    bridge.call_with_paths(bridge.encrypt_file, tmp_plaintext, enc, extra_kwargs={"key": key, "mode": mode})
    bridge.call_with_paths(bridge.decrypt_file, enc, dec, extra_kwargs={"key": key})
    assert dec.read_bytes() == tmp_plaintext.read_bytes()


def test_invalid_mode_raises(bridge: CryptoBridge, tmp_plaintext, tmp_path):
    if bridge.encrypt_file is None:
        pytest.skip("File encryption function not implemented")

    if not supports_mode(bridge):
        pytest.skip("Mode parameter not supported for encryption")

    key = random_key(bridge, 32)
    enc = tmp_path / "enc_invalid_mode.bin"
    with pytest.raises(Exception):
        bridge.call_with_paths(bridge.encrypt_file, tmp_plaintext, enc, extra_kwargs={"key": key, "mode": "INVALID_MODE"})


def test_decrypt_with_wrong_key_raises(bridge: CryptoBridge, tmp_plaintext, tmp_path):
    if bridge.encrypt_file is None or bridge.decrypt_file is None:
        pytest.skip("File encryption/decryption functions not implemented")

    key = random_key(bridge, 32)
    wrong_key = random_key(bridge, 32)
    enc = tmp_path / "enc_wrongkey.bin"
    dec = tmp_path / "dec_wrongkey.txt"
    bridge.call_with_paths(bridge.encrypt_file, tmp_plaintext, enc, extra_kwargs={"key": key})

    with pytest.raises(Exception):
        bridge.call_with_paths(bridge.decrypt_file, enc, dec, extra_kwargs={"key": wrong_key})