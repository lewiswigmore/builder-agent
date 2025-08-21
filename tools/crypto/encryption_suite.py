import os
import sys
import json
import base64
import shutil
import tempfile
import argparse
from typing import Optional, Tuple, Dict, Any

ETHICAL_WARNING = (
    "Ethical and Legal Notice:\n"
    "This encryption utility suite is provided strictly for authorized testing, education, and "
    "defensive security purposes. Do not use it to access, read, modify, or conceal data without "
    "explicit permission from the data owner and compliance with applicable laws and policies. "
    "Misuse may violate laws and result in severe penalties."
)

# External dependencies: cryptography
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, hmac, serialization, padding as sympadding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.exceptions import InvalidSignature, InvalidTag
except Exception as e:
    raise ImportError(
        "The 'cryptography' package is required for this tool. "
        "Install with: pip install cryptography"
    ) from e


# ---------------------------- Helpers ----------------------------

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def generate_random_bytes(n: int) -> bytes:
    if not isinstance(n, int) or n <= 0:
        raise ValueError("Length for random bytes must be a positive integer")
    return os.urandom(n)


def pbkdf2_derive_key(password: bytes, salt: Optional[bytes] = None, length: int = 32, iterations: int = 200_000, algorithm: hashes.HashAlgorithm = hashes.SHA256()) -> Tuple[bytes, bytes, int]:
    """
    Derive a key from a password using PBKDF2-HMAC.
    Returns (key, salt, iterations).
    """
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("Password must be bytes")
    if salt is None:
        salt = os.urandom(16)
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("Salt must be bytes with length >= 8")
    if length not in (16, 24, 32, 48, 64):
        # allow larger for key-splitting (e.g., enc+mac)
        raise ValueError("Length should be one of 16, 24, 32, 48, 64")
    kdf = PBKDF2HMAC(
        algorithm=algorithm,
        length=length,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password)
    return key, salt, iterations


def sha256_file(path: str) -> str:
    digest = hashes.Hash(hashes.SHA256())
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.finalize().hex()


def _derive_mac_key_from_key(base_key: bytes, iv: bytes) -> bytes:
    """
    Derive a 32-byte MAC key from a given base encryption key using HKDF with SHA-256.
    Salt is the IV/nonce and info is a fixed context string.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=iv,
        info=b"encsuite-file-mac",
    )
    return hkdf.derive(base_key)


# ---------------------------- AES Bytes ----------------------------

_SUPPORTED_AES_MODES = {"GCM": 1, "CBC": 2, "CTR": 3, "CFB": 4}
_MODE_CODE_TO_NAME = {v: k for k, v in _SUPPORTED_AES_MODES.items()}


def _new_cipher(key: bytes, mode: str, iv: bytes, tag: Optional[bytes] = None) -> Cipher:
    algo = algorithms.AES(key)
    if mode == "GCM":
        if tag is None:
            m = modes.GCM(iv)
        else:
            m = modes.GCM(iv, tag)
    elif mode == "CBC":
        m = modes.CBC(iv)
    elif mode == "CTR":
        m = modes.CTR(iv)
    elif mode == "CFB":
        m = modes.CFB(iv)
    else:
        raise ValueError(f"Unsupported AES mode: {mode}")
    return Cipher(algo, m)


def aes_encrypt_bytes(plaintext: bytes, key: bytes, mode: str = "GCM", iv: Optional[bytes] = None, aad: Optional[bytes] = None, mac_key: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Encrypt bytes using AES in the specified mode.
    For GCM, Tag is provided in output. For CBC/CTR/CFB, if mac_key is provided, returns HMAC for integrity.
    Returns dict with keys: ciphertext, iv, tag (GCM), hmac (CBC/CTR/CFB), mode.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext must be bytes")
    if not isinstance(key, (bytes, bytearray)) or len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    mode = mode.upper()
    if mode not in _SUPPORTED_AES_MODES:
        raise ValueError(f"Unsupported AES mode: {mode}")

    if mode == "GCM":
        iv = iv or os.urandom(12)
        encryptor = _new_cipher(key, "GCM", iv).encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        return {"ciphertext": ciphertext, "iv": iv, "tag": tag, "mode": "GCM"}
    else:
        iv_len = 16
        iv = iv or os.urandom(iv_len)
        encryptor = _new_cipher(key, mode, iv).encryptor()
        if mode == "CBC":
            padder = sympadding.PKCS7(128).padder()
            plaintext = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        result = {"ciphertext": ciphertext, "iv": iv, "mode": mode}
        if mac_key is not None:
            hm = hmac.HMAC(mac_key, hashes.SHA256())
            hm.update(iv)
            hm.update(ciphertext)
            result["hmac"] = hm.finalize()
        return result


def aes_decrypt_bytes(ciphertext: bytes, key: bytes, mode: str, iv: bytes, aad: Optional[bytes] = None, tag: Optional[bytes] = None, mac_key: Optional[bytes] = None) -> bytes:
    """
    Decrypt bytes using AES.
    For GCM, requires tag.
    For CBC/CTR/CFB with HMAC, caller should verify integrity separately (e.g., with file API).
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext must be bytes")
    if not isinstance(key, (bytes, bytearray)) or len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    mode = mode.upper()
    if mode == "GCM":
        if tag is None:
            raise ValueError("GCM requires authentication tag")
        decryptor = _new_cipher(key, "GCM", iv, tag).decryptor()
        if aad:
            decryptor.authenticate_additional_data(aad)
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag as e:
            raise InvalidTag("GCM authentication failed. Data may be tampered.") from e
        return plaintext
    else:
        decryptor = _new_cipher(key, mode, iv).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        if mode == "CBC":
            unpadder = sympadding.PKCS7(128).unpadder()
            try:
                return unpadder.update(padded) + unpadder.finalize()
            except ValueError as e:
                raise ValueError("Invalid padding or corrupted data.") from e
        else:
            return padded


# ---------------------------- File Encryption with Integrity ----------------------------

_MAGIC = b"ENCSUITE"
_VERSION = 1


def _build_metadata_dict(mode: str, iv: bytes, aad: Optional[bytes], kdf: Optional[str], salt: Optional[bytes], iterations: Optional[int], tag: Optional[bytes], hmac_value: Optional[bytes]) -> Dict[str, Any]:
    meta = {
        "mode": mode,
        "iv": b64e(iv),
        "aad": b64e(aad) if aad else None,
        "kdf": kdf,
        "salt": b64e(salt) if salt else None,
        "iterations": iterations,
        "tag": b64e(tag) if tag else None,
        "hmac": b64e(hmac_value) if hmac_value else None,
    }
    return meta


def _write_header_and_meta(fout, mode_code: int, meta: Dict[str, Any]) -> None:
    meta_bytes = json.dumps(meta, separators=(",", ":"), sort_keys=True).encode("utf-8")
    fout.write(_MAGIC)
    fout.write(bytes([_VERSION]))
    fout.write(bytes([mode_code]))
    fout.write(len(meta_bytes).to_bytes(4, "big"))
    fout.write(meta_bytes)


def encrypt_file(input_path: str, output_path: str, *, password: Optional[str] = None, key: Optional[bytes] = None, mode: str = "GCM", iterations: int = 200_000, aad: Optional[bytes] = None, chunk_size: int = 1024 * 1024) -> Dict[str, Any]:
    """
    Encrypt a file with integrity verification.
    - Default is AES-256-GCM with PBKDF2 (if password provided).
    - For CBC/CTR/CFB, HMAC-SHA256 is computed over (iv || ciphertext). When using password, keys are split from PBKDF2 output.
      When providing a raw key of 16/24/32 bytes, a MAC key is derived from the encryption key using HKDF with the IV.
    Returns metadata dict (including salt/iv/tag/hmac).
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")
    mode = mode.upper()
    if mode not in _SUPPORTED_AES_MODES:
        raise ValueError(f"Unsupported mode: {mode}")
    if not password and not key:
        raise ValueError("Provide either password or key")
    if password and not isinstance(password, str):
        raise TypeError("Password must be a string")
    if key and (not isinstance(key, (bytes, bytearray)) or len(key) not in (16, 24, 32, 64)):
        raise ValueError("Key must be 16, 24, 32, or 64 bytes")

    # Derive keys
    salt = None
    mac_key = None
    enc_key = None
    if password:
        # derive 32 bytes for GCM; for CBC/CTR/CFB derive 64 bytes and split
        pwd_bytes = password.encode("utf-8")
        if mode == "GCM":
            enc_key, salt, iterations = pbkdf2_derive_key(pwd_bytes, None, 32, iterations)
        else:
            combo_key, salt, iterations = pbkdf2_derive_key(pwd_bytes, None, 64, iterations)
            enc_key, mac_key = combo_key[:32], combo_key[32:]
    else:
        if mode == "GCM":
            enc_key = key[:32] if len(key) >= 32 else key
        else:
            if len(key) == 64:
                enc_key, mac_key = key[:32], key[32:]
            else:
                # accept single key; derive MAC key later using HKDF with IV
                enc_key = key if len(key) in (16, 24, 32) else None
                if enc_key is None:
                    raise ValueError("Invalid key length")

    # IV/nonce
    iv = os.urandom(12 if mode == "GCM" else 16)
    # Derive MAC key for non-GCM when not provided
    if mode != "GCM" and mac_key is None:
        mac_key = _derive_mac_key_from_key(enc_key, iv)

    temp_cipher_fd, temp_cipher_path = tempfile.mkstemp(prefix="encsuite_", suffix=".bin")
    os.close(temp_cipher_fd)
    hmac_ctx = hmac.HMAC(mac_key, hashes.SHA256()) if (mac_key is not None and mode != "GCM") else None

    try:
        with open(input_path, "rb") as fin, open(temp_cipher_path, "wb") as ftemp:
            if mode == "GCM":
                encryptor = _new_cipher(enc_key, "GCM", iv).encryptor()
                if aad:
                    encryptor.authenticate_additional_data(aad)
                for chunk in iter(lambda: fin.read(chunk_size), b""):
                    ftemp.write(encryptor.update(chunk))
                ftemp.write(encryptor.finalize())
                tag = encryptor.tag
                meta = _build_metadata_dict(mode, iv, aad, "pbkdf2" if password else None, salt, iterations if password else None, tag, None)
            else:
                encryptor = _new_cipher(enc_key, mode, iv).encryptor()
                if mode == "CBC":
                    padder = sympadding.PKCS7(128).padder()
                    for chunk in iter(lambda: fin.read(chunk_size), b""):
                        padded = padder.update(chunk)
                        if padded:
                            ftemp.write(encryptor.update(padded))
                    final_padded = padder.finalize()
                    if final_padded:
                        ftemp.write(encryptor.update(final_padded))
                    ftemp.write(encryptor.finalize())
                else:
                    # CTR/CFB
                    for chunk in iter(lambda: fin.read(chunk_size), b""):
                        ftemp.write(encryptor.update(chunk))
                    ftemp.write(encryptor.finalize())
                # compute HMAC over iv || ciphertext
                if hmac_ctx:
                    hmac_ctx.update(iv)
                    with open(temp_cipher_path, "rb") as ctfin:
                        for chunk in iter(lambda: ctfin.read(chunk_size), b""):
                            hmac_ctx.update(chunk)
                    hmac_value = hmac_ctx.finalize()
                else:
                    hmac_value = None
                meta = _build_metadata_dict(mode, iv, aad, "pbkdf2" if password else None, salt, iterations if password else None, None, hmac_value)

        # Write final output: header + meta + ciphertext
        with open(output_path, "wb") as fout, open(temp_cipher_path, "rb") as ftemp:
            _write_header_and_meta(fout, _SUPPORTED_AES_MODES[mode], meta)
            shutil.copyfileobj(ftemp, fout, length=chunk_size)

        return meta
    except Exception as e:
        # Ensure partial output is not left in an inconsistent state
        try:
            if os.path.exists(output_path):
                os.remove(output_path)
        except Exception:
            pass
        raise e
    finally:
        try:
            if os.path.exists(temp_cipher_path):
                os.remove(temp_cipher_path)
        except Exception:
            pass


def decrypt_file(input_path: str, output_path: str, *, password: Optional[str] = None, key: Optional[bytes] = None, chunk_size: int = 1024 * 1024) -> Dict[str, Any]:
    """
    Decrypt a file produced by encrypt_file. Verifies integrity (GCM tag or HMAC).
    Writes plaintext to output_path only after successful verification.
    Returns parsed metadata.
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Encrypted file not found: {input_path}")

    with open(input_path, "rb") as fin:
        magic = fin.read(len(_MAGIC))
        if magic != _MAGIC:
            raise ValueError("Invalid file format (magic mismatch)")
        version = fin.read(1)
        if not version or version[0] != _VERSION:
            raise ValueError(f"Unsupported file version: {version[0] if version else 'N/A'}")
        mode_code = fin.read(1)
        if not mode_code:
            raise ValueError("Corrupted file: missing mode code")
        mode = _MODE_CODE_TO_NAME.get(mode_code[0])
        if not mode:
            raise ValueError("Unknown encryption mode in file")
        meta_len_bytes = fin.read(4)
        if len(meta_len_bytes) != 4:
            raise ValueError("Corrupted file: missing metadata length")
        meta_len = int.from_bytes(meta_len_bytes, "big")
        meta_bytes = fin.read(meta_len)
        if len(meta_bytes) != meta_len:
            raise ValueError("Corrupted file: incomplete metadata")
        meta = json.loads(meta_bytes.decode("utf-8"))

        iv = b64d(meta["iv"])
        aad = b64d(meta["aad"]) if meta.get("aad") else None
        tag = b64d(meta["tag"]) if meta.get("tag") else None
        hmac_value = b64d(meta["hmac"]) if meta.get("hmac") else None
        kdf = meta.get("kdf")
        salt = b64d(meta["salt"]) if meta.get("salt") else None
        iterations = meta.get("iterations")

        # derive/validate keys
        enc_key = None
        mac_key = None
        if kdf == "pbkdf2":
            if not password:
                raise ValueError("Password required to decrypt this file")
            if not isinstance(password, str):
                raise TypeError("Password must be a string")
            pwd_bytes = password.encode("utf-8")
            if mode == "GCM":
                enc_key, _, _ = pbkdf2_derive_key(pwd_bytes, salt, 32, iterations)
            else:
                combo_key, _, _ = pbkdf2_derive_key(pwd_bytes, salt, 64, iterations)
                enc_key, mac_key = combo_key[:32], combo_key[32:]
        else:
            if not key:
                raise ValueError("Key required to decrypt this file")
            if mode == "GCM":
                enc_key = key[:32] if len(key) >= 32 else key
            else:
                if len(key) == 64:
                    enc_key, mac_key = key[:32], key[32:]
                elif len(key) in (16, 24, 32):
                    enc_key = key
                    mac_key = _derive_mac_key_from_key(enc_key, iv)
                else:
                    raise ValueError("For CBC/CTR/CFB, provide a 16/24/32-byte key (MAC derived) or a 64-byte key (enc+mac)")

        # Work with ciphertext stream after metadata
        temp_plain_fd, temp_plain_path = tempfile.mkstemp(prefix="encsuite_dec_", suffix=".bin")
        os.close(temp_plain_fd)

        try:
            # For integrity, buffer ciphertext into temp file and verify before producing plaintext
            temp_cipher_fd, temp_cipher_path = tempfile.mkstemp(prefix="encsuite_buf_", suffix=".bin")
            os.close(temp_cipher_fd)
            try:
                with open(temp_cipher_path, "wb") as ctemp:
                    shutil.copyfileobj(fin, ctemp, length=chunk_size)

                # Integrity verification
                if mode == "GCM":
                    # Tag verification is done during finalize; decrypt into temp file
                    with open(temp_cipher_path, "rb") as ctemp, open(temp_plain_path, "wb") as ptemp:
                        decryptor = _new_cipher(enc_key, "GCM", iv, tag).decryptor()
                        if aad:
                            decryptor.authenticate_additional_data(aad)
                        for chunk in iter(lambda: ctemp.read(chunk_size), b""):
                            ptemp.write(decryptor.update(chunk))
                        try:
                            ptemp.write(decryptor.finalize())
                        except InvalidTag as e:
                            raise InvalidTag("GCM authentication failed. File may be corrupted or tampered.") from e
                else:
                    # Verify HMAC over iv || ciphertext first
                    if not mac_key or not hmac_value:
                        raise ValueError("Missing HMAC for integrity verification")
                    hm = hmac.HMAC(mac_key, hashes.SHA256())
                    hm.update(iv)
                    with open(temp_cipher_path, "rb") as ctemp:
                        for chunk in iter(lambda: ctemp.read(chunk_size), b""):
                            hm.update(chunk)
                    try:
                        hm.verify(hmac_value)
                    except InvalidSignature as e:
                        raise InvalidSignature("HMAC verification failed. File integrity compromised.") from e
                    # HMAC OK, decrypt to temp plaintext
                    with open(temp_cipher_path, "rb") as ctemp, open(temp_plain_path, "wb") as ptemp:
                        decryptor = _new_cipher(enc_key, mode, iv).decryptor()
                        if mode == "CBC":
                            # Need to handle padding after finalize
                            buf = b""
                            for chunk in iter(lambda: ctemp.read(chunk_size), b""):
                                buf += decryptor.update(chunk)
                                if len(buf) > 2 * 1024 * 1024:
                                    ptemp.write(buf)
                                    buf = b""
                            buf += decryptor.finalize()
                            # unpad
                            unpadder = sympadding.PKCS7(128).unpadder()
                            try:
                                plaintext = unpadder.update(buf) + unpadder.finalize()
                            except ValueError as e:
                                raise ValueError("Invalid padding or corrupted data.") from e
                            ptemp.write(plaintext)
                        else:
                            for chunk in iter(lambda: ctemp.read(chunk_size), b""):
                                ptemp.write(decryptor.update(chunk))
                            ptemp.write(decryptor.finalize())

                # Move temp plaintext to final output
                shutil.copyfile(temp_plain_path, output_path)
                return meta
            finally:
                try:
                    if os.path.exists(temp_cipher_path):
                        os.remove(temp_cipher_path)
                except Exception:
                    pass
        finally:
            try:
                if os.path.exists(temp_plain_path):
                    os.remove(temp_plain_path)
            except Exception:
                pass


# ---------------------------- RSA Operations ----------------------------

def rsa_generate_keypair(key_size: int = 2048, public_exponent: int = 65537, password: Optional[str] = None) -> Tuple[bytes, bytes]:
    """
    Generate RSA private/public key pair. Returns (private_pem, public_pem).
    If password is provided, the private key PEM is encrypted with best available algorithm.
    """
    if key_size < 2048:
        raise ValueError("RSA key size must be at least 2048 bits for security")
    private_key = rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size)
    enc_alg = serialization.NoEncryption()
    if password is not None:
        if not isinstance(password, str):
            raise TypeError("Password must be a string")
        enc_alg = serialization.BestAvailableEncryption(password.encode("utf-8"))
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_alg,
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def rsa_encrypt(public_key: bytes, message: bytes) -> bytes:
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("Plaintext must be bytes")
    pub = serialization.load_pem_public_key(public_key)
    ciphertext = pub.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return ciphertext


def rsa_decrypt(private_key: bytes, ciphertext: bytes, password: Optional[str] = None) -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext must be bytes")
    priv = serialization.load_pem_private_key(private_key, password=password.encode("utf-8") if isinstance(password, str) else password)
    plaintext = priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return plaintext


def rsa_sign(private_key: bytes, message: bytes, password: Optional[str] = None) -> bytes:
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("Message must be bytes")
    priv = serialization.load_pem_private_key(private_key, password=password.encode("utf-8") if isinstance(password, str) else password)
    signature = priv.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return signature


def rsa_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    pub = serialization.load_pem_public_key(public_key)
    try:
        pub.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ---------------------------- CLI ----------------------------

def _cli():
    print(ETHICAL_WARNING, file=sys.stderr)
    parser = argparse.ArgumentParser(description="Encryption Utility Suite - Authorized testing only.")
    sub = parser.add_subparsers(dest="cmd")

    # Random
    p_rand = sub.add_parser("rand", help="Generate secure random bytes")
    p_rand.add_argument("length", type=int, help="Number of bytes to generate")
    p_rand.add_argument("--out", help="Output file (defaults to stdout base64)")

    # PBKDF2
    p_kdf = sub.add_parser("pbkdf2", help="Derive a key using PBKDF2")
    p_kdf.add_argument("password", help="Password")
    p_kdf.add_argument("--length", type=int, default=32)
    p_kdf.add_argument("--iterations", type=int, default=200000)

    # RSA
    p_rsa_gen = sub.add_parser("gen-rsa", help="Generate RSA key pair")
    p_rsa_gen.add_argument("--bits", type=int, default=2048)
    p_rsa_gen.add_argument("--password", help="Password to encrypt private key (optional)")
    p_rsa_gen.add_argument("--out-priv", required=True, help="Private key PEM output path")
    p_rsa_gen.add_argument("--out-pub", required=True, help="Public key PEM output path")

    # AES file encrypt/decrypt
    p_enc = sub.add_parser("aes-encrypt-file", help="Encrypt a file (AES with integrity)")
    p_enc.add_argument("input", help="Input file")
    p_enc.add_argument("output", help="Output encrypted file")
    p_enc.add_argument("--mode", choices=["GCM", "CBC", "CTR", "CFB"], default="GCM")
    p_enc.add_argument("--password", help="Password for PBKDF2 (recommended)")
    p_enc.add_argument("--key", help="Hex key (32 bytes for GCM, 16/24/32/64 bytes for CBC/CTR/CFB)")
    p_enc.add_argument("--aad", help="Base64 AAD for AEAD modes (GCM)")

    p_dec = sub.add_parser("aes-decrypt-file", help="Decrypt a file (verifies integrity)")
    p_dec.add_argument("input", help="Input encrypted file")
    p_dec.add_argument("output", help="Output decrypted file")
    p_dec.add_argument("--password", help="Password if password-based encryption was used")
    p_dec.add_argument("--key", help="Hex key if key-based encryption was used")

    args = parser.parse_args()
    if args.cmd == "rand":
        data = generate_random_bytes(args.length)
        if args.out:
            with open(args.out, "wb") as f:
                f.write(data)
            print(f"Wrote {args.length} random bytes to {args.out}")
        else:
            print(b64e(data))
    elif args.cmd == "pbkdf2":
        key, salt, iters = pbkdf2_derive_key(args.password.encode("utf-8"), None, args.length, args.iterations)
        print(json.dumps({"key_b64": b64e(key), "salt_b64": b64e(salt), "iterations": iters}))
    elif args.cmd == "gen-rsa":
        priv, pub = rsa_generate_keypair(args.bits, 65537, args.password)
        with open(args.out_priv, "wb") as f:
            f.write(priv)
        with open(args.out_pub, "wb") as f:
            f.write(pub)
        print(f"Generated RSA keys: {args.out_priv}, {args.out_pub}")
    elif args.cmd == "aes-encrypt-file":
        if not args.password and not args.key:
            print("Error: provide --password or --key", file=sys.stderr)
            sys.exit(2)
        key = bytes.fromhex(args.key) if args.key else None
        aad = base64.b64decode(args.aad) if args.aad else None
        meta = encrypt_file(args.input, args.output, password=args.password, key=key, mode=args.mode, aad=aad)
        print(json.dumps(meta, indent=2))
    elif args.cmd == "aes-decrypt-file":
        key = bytes.fromhex(args.key) if args.key else None
        meta = decrypt_file(args.input, args.output, password=args.password, key=key)
        print(json.dumps(meta, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    _cli()