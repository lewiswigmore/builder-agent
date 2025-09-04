import os
import io
import json
import hashlib
import importlib
import secrets
import pytest

enc = importlib.import_module("tools.crypto.encryption_suite")


def has_attr(name):
    return hasattr(enc, name)


@pytest.fixture
def sample_data():
    return b"The quick brown fox jumps over the lazy dog"


@pytest.fixture
def random_key_32():
    if has_attr("generate_secure_random_key"):
        return enc.generate_secure_random_key(32)
    # fallback if not implemented
    return secrets.token_bytes(32)


@pytest.fixture
def tmp_text_file(tmp_path):
    p = tmp_path / "plain.txt"
    content = b"Hello, Encryption Utility Suite!\n" * 50
    p.write_bytes(content)
    return p


def _aes_encrypt(mode, plaintext, key, aad=None):
    assert has_attr("encrypt_aes"), "encrypt_aes not implemented"
    # Try calling encrypt_aes and normalize its return
    res = None
    try:
        if aad is not None:
            res = enc.encrypt_aes(plaintext, key, mode=mode, aad=aad)
        else:
            res = enc.encrypt_aes(plaintext, key, mode=mode)
    except TypeError:
        # Some implementations may not accept aad kwarg
        res = enc.encrypt_aes(plaintext, key, mode=mode)

    # Normalize result
    if isinstance(res, dict):
        # Expect keys: ciphertext, iv/nonce, maybe tag
        ct = res.get("ciphertext")
        iv = res.get("iv") or res.get("nonce")
        tag = res.get("tag")
        return ct, iv, tag
    elif isinstance(res, (tuple, list)):
        if len(res) == 3:
            return res[0], res[1], res[2]
        elif len(res) == 2:
            return res[0], res[1], None
        else:
            raise AssertionError("encrypt_aes returned unexpected tuple length")
    elif isinstance(res, (bytes, bytearray)):
        # If only ciphertext returned, we can't decrypt without iv/tag; fail test
        raise AssertionError("encrypt_aes returned only ciphertext without iv/tag")
    else:
        raise AssertionError("encrypt_aes returned unexpected type")


def _aes_decrypt(mode, ciphertext, key, iv=None, tag=None, aad=None):
    assert has_attr("decrypt_aes"), "decrypt_aes not implemented"
    try:
        if aad is not None:
            return enc.decrypt_aes(ciphertext, key, mode=mode, iv=iv, tag=tag, aad=aad)
        else:
            return enc.decrypt_aes(ciphertext, key, mode=mode, iv=iv, tag=tag)
    except TypeError:
        # Some implementations may not accept aad kwarg
        return enc.decrypt_aes(ciphertext, key, mode=mode, iv=iv, tag=tag)


@pytest.mark.parametrize("mode", ["GCM", "CBC", "CFB"])
def test_aes_encrypt_decrypt_multiple_modes(mode, sample_data, random_key_32):
    if not (has_attr("encrypt_aes") and has_attr("decrypt_aes")):
        pytest.skip("AES functions not implemented")

    aad = b"associated-data" if mode.upper() == "GCM" else None
    ct, iv, tag = _aes_encrypt(mode, sample_data, random_key_32, aad=aad)
    assert isinstance(ct, (bytes, bytearray)) and len(ct) > 0
    assert isinstance(iv, (bytes, bytearray)) and len(iv) > 0
    if mode.upper() == "GCM":
        assert isinstance(tag, (bytes, bytearray)) and len(tag) > 0
    pt = _aes_decrypt(mode, ct, random_key_32, iv=iv, tag=tag, aad=aad)
    assert pt == sample_data


def test_aes_invalid_mode_raises(sample_data, random_key_32):
    if not has_attr("encrypt_aes"):
        pytest.skip("AES functions not implemented")
    with pytest.raises(Exception):
        enc.encrypt_aes(sample_data, random_key_32, mode="INVALID_MODE")


@pytest.mark.parametrize("bad_key", [b"", b"\x00" * 5, b"\x01" * 17])
def test_aes_invalid_key_length_raises(sample_data, bad_key):
    if not has_attr("encrypt_aes"):
        pytest.skip("AES functions not implemented")
    with pytest.raises(Exception):
        enc.encrypt_aes(sample_data, bad_key, mode="GCM")


def test_generate_secure_rsa_key_pairs():
    if not has_attr("generate_rsa_keypair"):
        pytest.skip("RSA not implemented")
    priv, pub = enc.generate_rsa_keypair(2048)
    assert priv and pub
    # Accept strings or bytes or key objects; basic sanity
    assert priv != pub


def test_rsa_encrypt_decrypt_and_sign_verify(sample_data):
    if not all(has_attr(n) for n in ["generate_rsa_keypair", "rsa_encrypt", "rsa_decrypt", "rsa_sign", "rsa_verify"]):
        pytest.skip("RSA operations not fully implemented")
    priv, pub = enc.generate_rsa_keypair(2048)
    ct = enc.rsa_encrypt(pub, sample_data)
    assert isinstance(ct, (bytes, bytearray))
    pt = enc.rsa_decrypt(priv, ct)
    assert pt == sample_data

    sig = enc.rsa_sign(priv, sample_data)
    assert isinstance(sig, (bytes, bytearray))
    assert enc.rsa_verify(pub, sample_data, sig) is True
    # Negative verification
    assert enc.rsa_verify(pub, sample_data + b"x", sig) is False


def test_rsa_decrypt_invalid_ciphertext_raises():
    if not all(has_attr(n) for n in ["generate_rsa_keypair", "rsa_decrypt"]):
        pytest.skip("RSA decrypt not implemented")
    priv, _ = enc.generate_rsa_keypair(2048)
    with pytest.raises(Exception):
        enc.rsa_decrypt(priv, b"\x00\x01\x02")


def test_secure_random_key_generation():
    if not has_attr("generate_secure_random_key"):
        pytest.skip("Secure random key function not implemented")
    k1 = enc.generate_secure_random_key(32)
    k2 = enc.generate_secure_random_key(32)
    assert isinstance(k1, (bytes, bytearray)) and len(k1) == 32
    assert isinstance(k2, (bytes, bytearray)) and len(k2) == 32
    assert k1 != k2


def test_pbkdf2_derivation_deterministic():
    if not has_attr("derive_key_pbkdf2"):
        pytest.skip("PBKDF2 not implemented")
    password = "correct horse battery staple"
    salt = secrets.token_bytes(16)
    k1 = enc.derive_key_pbkdf2(password, salt=salt, iterations=100_000, length=32, hash_name="sha256")
    k2 = enc.derive_key_pbkdf2(password, salt=salt, iterations=100_000, length=32, hash_name="sha256")
    assert isinstance(k1, (bytes, bytearray)) and len(k1) == 32
    assert k1 == k2
    # Different salt leads to different keys
    salt2 = secrets.token_bytes(16)
    k3 = enc.derive_key_pbkdf2(password, salt=salt2, iterations=100_000, length=32, hash_name="sha256")
    assert k1 != k3


def test_pbkdf2_returns_salt_when_none_provided():
    if not has_attr("derive_key_pbkdf2"):
        pytest.skip("PBKDF2 not implemented")
    password = "secret"
    res = enc.derive_key_pbkdf2(password, salt=None, iterations=50_000, length=16, hash_name="sha256")
    if isinstance(res, (tuple, list)):
        key, salt = res
        assert isinstance(key, (bytes, bytearray)) and len(key) == 16
        assert isinstance(salt, (bytes, bytearray)) and len(salt) >= 8
        # Calling again with returned salt yields same key
        key2 = enc.derive_key_pbkdf2(password, salt=salt, iterations=50_000, length=16, hash_name="sha256")
        assert key == key2
    else:
        # If implementation does not return salt, at least ensure key length
        assert isinstance(res, (bytes, bytearray)) and len(res) == 16


def test_encrypt_and_decrypt_file_successfully(tmp_text_file, tmp_path, random_key_32):
    if not all(has_attr(n) for n in ["encrypt_file", "decrypt_file"]):
        pytest.skip("File encryption not implemented")
    enc_path = tmp_path / "cipher.bin"
    dec_path = tmp_path / "decrypted.txt"
    meta = enc.encrypt_file(str(tmp_text_file), str(enc_path), key=random_key_32, mode="GCM")
    assert enc_path.exists() and enc_path.stat().st_size > 0
    # meta may be None or contain iv/tag/hash; accept both
    enc.decrypt_file(str(enc_path), str(dec_path), key=random_key_32)
    assert dec_path.read_bytes() == tmp_text_file.read_bytes()


def test_verify_file_integrity_after_tamper(tmp_text_file, tmp_path, random_key_32):
    if not all(has_attr(n) for n in ["encrypt_file", "decrypt_file"]):
        pytest.skip("File encryption not implemented")
    enc_path = tmp_path / "cipher2.bin"
    dec_path = tmp_path / "decrypted2.txt"
    enc.encrypt_file(str(tmp_text_file), str(enc_path), key=random_key_32, mode="GCM")
    data = bytearray(enc_path.read_bytes())
    # flip a byte near the middle
    if data:
        idx = len(data) // 2
        data[idx] ^= 0xFF
        enc_path.write_bytes(bytes(data))
    with pytest.raises(Exception):
        enc.decrypt_file(str(enc_path), str(dec_path), key=random_key_32)


def test_handle_password_based_encryption(tmp_text_file, tmp_path):
    if not all(has_attr(n) for n in ["encrypt_file", "decrypt_file"]):
        pytest.skip("File encryption not implemented")
    password = "S3cure-P@ssw0rd!"
    enc_path = tmp_path / "cipher_pw.bin"
    dec_path = tmp_path / "decrypted_pw.txt"
    # Expect implementation to support password=... for PBKDF2-based encryption
    enc.encrypt_file(str(tmp_text_file), str(enc_path), password=password, mode="GCM")
    enc.decrypt_file(str(enc_path), str(dec_path), password=password)
    assert dec_path.read_bytes() == tmp_text_file.read_bytes()


def test_password_based_encryption_wrong_password_fails(tmp_text_file, tmp_path):
    if not all(has_attr(n) for n in ["encrypt_file", "decrypt_file"]):
        pytest.skip("File encryption not implemented")
    enc_path = tmp_path / "cipher_pw2.bin"
    dec_path = tmp_path / "decrypted_pw2.txt"
    enc.encrypt_file(str(tmp_text_file), str(enc_path), password="right-pass", mode="GCM")
    with pytest.raises(Exception):
        enc.decrypt_file(str(enc_path), str(dec_path), password="wrong-pass")


def test_file_encryption_requires_key_or_password(tmp_text_file, tmp_path):
    if not has_attr("encrypt_file"):
        pytest.skip("File encryption not implemented")
    enc_path = tmp_path / "cipher_err.bin"
    with pytest.raises(Exception):
        enc.encrypt_file(str(tmp_text_file), str(enc_path))