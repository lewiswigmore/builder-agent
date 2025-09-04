"""
Encryption Utility Suite
Category: cryptography
Description: Comprehensive encryption/decryption tool with multiple cipher support.

IMPORTANT ETHICAL NOTICE:
- This tool is intended strictly for lawful, authorized use such as protecting your own data,
  conducting organizational security tasks with explicit permission, or learning in a safe,
  legal setting.
- Do not use this tool to access, modify, or interfere with data for which you do not have
  clear authorization. Misuse may violate laws and policies and can result in severe penalties.

Features:
- AES encryption/decryption with multiple modes (GCM with integrity; CBC for compatibility).
- RSA key generation and operations (encryption/decryption, sign/verify).
- Secure random key generation utilities.
- File encryption with integrity verification (AES-GCM).
- Password-based key derivation (PBKDF2-HMAC-SHA256).

Acceptance Scenarios:
- Encrypt and decrypt a test file successfully.
- Generate secure RSA key pairs.
- Verify file integrity after encryption/decryption (AES-GCM provides AEAD).
- Handle password-based encryption (PBKDF2-derived AES-256 key).

Note:
- AES-GCM is recommended for most use cases because it provides authenticated encryption.
- AES-CBC implemented here does NOT include an HMAC; it provides confidentiality only and
  should not be used when integrity/authenticity is required unless combined with a MAC.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import struct
from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ----------------------------
# Constants and Exceptions
# ----------------------------

SUPPORTED_AES_MODES = {"GCM", "CBC"}

MAGIC = b"ESU1"  # File format magic/version: Encryption Suite Utility v1
HEADER_LEN_SIZE = 4  # 4 bytes big-endian uint for header length

class EncryptionSuiteError(Exception):
    """Base exception for the Encryption Utility Suite."""

class EncryptionError(EncryptionSuiteError):
    """Raised when encryption fails."""

class DecryptionError(EncryptionSuiteError):
    """Raised when decryption fails."""

class IntegrityError(EncryptionSuiteError):
    """Raised when integrity/authentication checks fail."""

class KeyGenerationError(EncryptionSuiteError):
    """Raised when key generation or derivation fails."""

class RSAError(EncryptionSuiteError):
    """Raised for RSA-related errors."""

class FileFormatError(EncryptionSuiteError):
    """Raised when the encrypted file format is invalid or unsupported."""


# ----------------------------
# Utilities
# ----------------------------

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))

def secure_random_bytes(n: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Args:
        n: Number of bytes to generate.

    Returns:
        Random bytes of length n.
    """
    if not isinstance(n, int) or n <= 0:
        raise KeyGenerationError("Byte count must be a positive integer.")
    return secrets.token_bytes(n)

def generate_aes_key(length: int = 32) -> bytes:
    """
    Generate a secure random AES key.

    Args:
        length: Key length in bytes. Valid lengths: 16 (AES-128), 24 (AES-192), 32 (AES-256).

    Returns:
        Random AES key.

    Raises:
        KeyGenerationError: If an unsupported length is provided.
    """
    if length not in (16, 24, 32):
        raise KeyGenerationError("AES key length must be one of 16, 24, or 32 bytes.")
    return secure_random_bytes(length)

def pbkdf2_derive_key(
    password: Union[str, bytes],
    salt: Optional[bytes] = None,
    length: int = 32,
    iterations: int = 200_000,
) -> Tuple[bytes, bytes]:
    """
    Derive a key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: The input password.
        salt: Optional salt. If None, a new random salt is generated.
        length: Desired key length in bytes (default 32 for AES-256).
        iterations: PBKDF2 iteration count (default 200,000).

    Returns:
        (key, salt) tuple.

    Raises:
        KeyGenerationError: On invalid parameters.
    """
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    elif isinstance(password, (bytes, bytearray)):
        password_bytes = bytes(password)
    else:
        raise KeyGenerationError("Password must be of type str or bytes.")

    if salt is None:
        salt = secure_random_bytes(16)
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise KeyGenerationError("Salt must be bytes and at least 8 bytes long.")
    if not isinstance(iterations, int) or iterations < 50_000:
        raise KeyGenerationError("Iterations must be an integer >= 50,000.")
    if length not in (16, 24, 32):
        raise KeyGenerationError("Derived key length must be 16, 24, or 32 bytes.")

    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=bytes(salt),
            iterations=iterations,
        )
        key = kdf.derive(password_bytes)
        return key, bytes(salt)
    except Exception as exc:
        raise KeyGenerationError(f"PBKDF2 derivation failed: {exc}") from exc


# ----------------------------
# AES (Symmetric) Operations
# ----------------------------

def aes_encrypt(
    data: bytes,
    key: bytes,
    mode: str = "GCM",
    associated_data: Optional[bytes] = None,
) -> dict:
    """
    Encrypt data using AES.

    Supported modes:
      - GCM (recommended; provides authenticity/integrity)
      - CBC (confidentiality only; NO integrity protection)

    Args:
        data: Plaintext bytes.
        key: AES key (16/24/32 bytes).
        mode: 'GCM' or 'CBC'.
        associated_data: Optional AAD for GCM.

    Returns:
        A dictionary containing ciphertext and parameters required for decryption.

    Raises:
        EncryptionError: On error or invalid parameters.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise EncryptionError("Data must be bytes.")
    if not isinstance(key, (bytes, bytearray)) or len(key) not in (16, 24, 32):
        raise EncryptionError("Key must be 16, 24, or 32 bytes.")
    mode = mode.upper()
    if mode not in SUPPORTED_AES_MODES:
        raise EncryptionError(f"Unsupported AES mode '{mode}'. Supported: {sorted(SUPPORTED_AES_MODES)}.")

    try:
        if mode == "GCM":
            nonce = secure_random_bytes(12)
            aesgcm = AESGCM(bytes(key))
            ct = aesgcm.encrypt(nonce, bytes(data), associated_data)
            return {
                "mode": "GCM",
                "nonce": _b64e(nonce),
                "ciphertext": _b64e(ct),
                "aad_present": associated_data is not None,
            }
        else:  # CBC
            iv = secure_random_bytes(16)
            cipher = Cipher(algorithms.AES(bytes(key)), modes.CBC(iv))
            encryptor = cipher.encryptor()
            padder = sym_padding.PKCS7(128).padder()
            padded = padder.update(bytes(data)) + padder.finalize()
            ct = encryptor.update(padded) + encryptor.finalize()
            return {
                "mode": "CBC",
                "iv": _b64e(iv),
                "ciphertext": _b64e(ct),
            }
    except Exception as exc:
        raise EncryptionError(f"AES encryption failed: {exc}") from exc

def aes_decrypt(
    blob: dict,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Decrypt data previously encrypted with aes_encrypt.

    Args:
        blob: Dictionary returned by aes_encrypt.
        key: AES key (16/24/32 bytes).
        associated_data: AAD, required if used during GCM encryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        IntegrityError: If GCM authentication fails.
        DecryptionError: On any other failure.
    """
    if not isinstance(blob, dict):
        raise DecryptionError("Input must be a dict produced by aes_encrypt.")
    if not isinstance(key, (bytes, bytearray)) or len(key) not in (16, 24, 32):
        raise DecryptionError("Key must be 16, 24, or 32 bytes.")

    mode = blob.get("mode", "").upper()
    try:
        if mode == "GCM":
            nonce_b64 = blob.get("nonce")
            ct_b64 = blob.get("ciphertext")
            if not nonce_b64 or not ct_b64:
                raise DecryptionError("Missing nonce or ciphertext for GCM mode.")
            nonce = _b64d(nonce_b64)
            ct = _b64d(ct_b64)
            aesgcm = AESGCM(bytes(key))
            try:
                return aesgcm.decrypt(nonce, ct, associated_data)
            except InvalidTag as exc:
                raise IntegrityError("Authentication failed. Wrong key/password, AAD, or data was tampered.") from exc
        elif mode == "CBC":
            iv_b64 = blob.get("iv")
            ct_b64 = blob.get("ciphertext")
            if not iv_b64 or not ct_b64:
                raise DecryptionError("Missing IV or ciphertext for CBC mode.")
            iv = _b64d(iv_b64)
            ct = _b64d(ct_b64)
            cipher = Cipher(algorithms.AES(bytes(key)), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            data = unpadder.update(padded) + unpadder.finalize()
            return data
        else:
            raise DecryptionError(f"Unsupported AES mode '{mode}'.")
    except IntegrityError:
        raise
    except Exception as exc:
        raise DecryptionError(f"AES decryption failed: {exc}") from exc


# ----------------------------
# File Encryption (AES-GCM)
# ----------------------------

def encrypt_file(
    input_path: str,
    output_path: str,
    key: Optional[bytes] = None,
    *,
    password: Optional[Union[str, bytes]] = None,
    iterations: int = 200_000,
    associated_data: Optional[bytes] = None,
) -> None:
    """
    Encrypt a file using AES-256-GCM with optional password-based key derivation (PBKDF2).

    File format:
        MAGIC (4 bytes: 'ESU1')
        HEADER_LEN (4 bytes, big-endian)
        HEADER (JSON utf-8):
            {
              "version": 1,
              "aead": "AESGCM",
              "kdf": "NONE" | "PBKDF2HMAC",
              "iterations": <int>,            # present if kdf != NONE
              "salt": "<b64>",                 # present if kdf != NONE
              "nonce": "<b64>"
            }
        CIPHERTEXT (bytes): AESGCM ciphertext including tag

    Args:
        input_path: Path to plaintext input file.
        output_path: Path to write encrypted file.
        key: Optional raw AES key (32 bytes recommended). Mutually exclusive with password.
        password: Optional password for PBKDF2 key derivation (AES-256). Mutually exclusive with key.
        iterations: PBKDF2 iterations if password is used.
        associated_data: Optional AAD used in AEAD. Must be provided again to decrypt.

    Raises:
        EncryptionError: On encryption or parameter errors.
    """
    if (key is None and password is None) or (key is not None and password is not None):
        raise EncryptionError("Provide exactly one of 'key' or 'password'.")
    if key is not None and len(key) not in (16, 24, 32):
        raise EncryptionError("AES key must be 16, 24, or 32 bytes.")
    try:
        with open(input_path, "rb") as f:
            plaintext = f.read()
    except Exception as exc:
        raise EncryptionError(f"Could not read input file: {exc}") from exc

    try:
        if password is not None:
            derived_key, salt = pbkdf2_derive_key(password, salt=None, length=32, iterations=iterations)
            kdf_name = "PBKDF2HMAC"
            kdf_iterations = iterations
            kdf_salt = salt
            aes_key = derived_key
        else:
            kdf_name = "NONE"
            kdf_iterations = None
            kdf_salt = None
            aes_key = bytes(key)

        nonce = secure_random_bytes(12)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        header = {
            "version": 1,
            "aead": "AESGCM",
            "kdf": kdf_name,
            "nonce": _b64e(nonce),
        }
        if kdf_name != "NONE":
            header["iterations"] = int(kdf_iterations)
            header["salt"] = _b64e(kdf_salt)

        header_json = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        header_len = struct.pack(">I", len(header_json))

        tmp_output_path = output_path + ".tmp"

        with open(tmp_output_path, "wb") as out:
            out.write(MAGIC)
            out.write(header_len)
            out.write(header_json)
            out.write(ciphertext)

        # Atomic-ish rename
        os.replace(tmp_output_path, output_path)
    except Exception as exc:
        # Clean up tmp file if present
        try:
            if "tmp_output_path" in locals() and os.path.exists(tmp_output_path):
                os.remove(tmp_output_path)
        except Exception:
            pass
        if isinstance(exc, EncryptionSuiteError):
            raise
        raise EncryptionError(f"File encryption failed: {exc}") from exc

def decrypt_file(
    input_path: str,
    output_path: str,
    key: Optional[bytes] = None,
    *,
    password: Optional[Union[str, bytes]] = None,
    associated_data: Optional[bytes] = None,
) -> None:
    """
    Decrypt a file previously encrypted with encrypt_file (AES-256-GCM).

    Args:
        input_path: Path to encrypted file.
        output_path: Path to write decrypted plaintext.
        key: Optional raw AES key; mutually exclusive with password.
        password: Optional password for PBKDF2; mutually exclusive with key.
        associated_data: Optional AAD, must match what was used for encryption.

    Raises:
        FileFormatError: If the file header is malformed/unsupported.
        IntegrityError: If authentication fails (wrong password/key/AAD, or tampering).
        DecryptionError: On other failures.
    """
    if (key is None and password is None) or (key is not None and password is not None):
        raise DecryptionError("Provide exactly one of 'key' or 'password'.")
    if key is not None and len(key) not in (16, 24, 32):
        raise DecryptionError("AES key must be 16, 24, or 32 bytes.")

    try:
        with open(input_path, "rb") as f:
            header_magic = f.read(len(MAGIC))
            if header_magic != MAGIC:
                raise FileFormatError("Invalid file magic/version.")
            header_len_bytes = f.read(HEADER_LEN_SIZE)
            if len(header_len_bytes) != HEADER_LEN_SIZE:
                raise FileFormatError("Invalid file header length.")
            header_len = struct.unpack(">I", header_len_bytes)[0]
            header_json = f.read(header_len)
            if len(header_json) != header_len:
                raise FileFormatError("Truncated header.")
            try:
                header = json.loads(header_json.decode("utf-8"))
            except Exception as exc:
                raise FileFormatError(f"Corrupted header JSON: {exc}") from exc

            if header.get("version") != 1 or header.get("aead") != "AESGCM":
                raise FileFormatError("Unsupported file version or AEAD.")

            nonce_b64 = header.get("nonce")
            if not nonce_b64:
                raise FileFormatError("Missing nonce in header.")
            nonce = _b64d(nonce_b64)

            kdf = header.get("kdf", "NONE")
            if kdf == "NONE":
                if key is None:
                    raise DecryptionError("This file requires a raw AES key.")
                aes_key = bytes(key)
            elif kdf == "PBKDF2HMAC":
                if password is None:
                    raise DecryptionError("This file requires a password for PBKDF2.")
                iterations = header.get("iterations")
                salt_b64 = header.get("salt")
                if not isinstance(iterations, int) or not salt_b64:
                    raise FileFormatError("Missing KDF parameters (iterations/salt).")
                salt = _b64d(salt_b64)
                aes_key, _ = pbkdf2_derive_key(password, salt=salt, length=32, iterations=int(iterations))
            else:
                raise FileFormatError(f"Unsupported KDF '{kdf}'.")

            ciphertext = f.read()
            if not ciphertext:
                raise FileFormatError("Missing ciphertext.")
    except (FileFormatError, DecryptionError):
        raise
    except Exception as exc:
        raise DecryptionError(f"Failed to read encrypted file: {exc}") from exc

    try:
        aesgcm = AESGCM(aes_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag as exc:
            raise IntegrityError("Authentication failed. Wrong key/password/AAD, or data tampered.") from exc

        tmp_output_path = output_path + ".tmp"
        with open(tmp_output_path, "wb") as out:
            out.write(plaintext)
        os.replace(tmp_output_path, output_path)
    except IntegrityError:
        raise
    except Exception as exc:
        try:
            if "tmp_output_path" in locals() and os.path.exists(tmp_output_path):
                os.remove(tmp_output_path)
        except Exception:
            pass
        raise DecryptionError(f"File decryption failed: {exc}") from exc


# ----------------------------
# RSA Operations
# ----------------------------

def generate_rsa_keypair(
    key_size: int = 2048,
    public_exponent: int = 65537,
    *,
    password: Optional[Union[str, bytes]] = None,
) -> Tuple[bytes, bytes]:
    """
    Generate an RSA key pair.

    Args:
        key_size: RSA modulus size in bits (e.g., 2048, 3072, 4096).
        public_exponent: Usually 65537.
        password: Optional password to encrypt the private key (PEM). If provided,
                  BestAvailableEncryption is used.

    Returns:
        (private_pem, public_pem) as bytes.

    Raises:
        KeyGenerationError: On failure or invalid parameters.
    """
    if not isinstance(key_size, int) or key_size < 2048:
        raise KeyGenerationError("RSA key_size must be an integer >= 2048.")
    if public_exponent not in (3, 65537):
        raise KeyGenerationError("public_exponent must be 3 or 65537.")
    try:
        private_key = rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size)
        if password is None:
            enc_alg = serialization.NoEncryption()
        else:
            if isinstance(password, str):
                password_bytes = password.encode("utf-8")
            elif isinstance(password, (bytes, bytearray)):
                password_bytes = bytes(password)
            else:
                raise KeyGenerationError("Password must be str or bytes.")
            enc_alg = serialization.BestAvailableEncryption(password_bytes)
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc_alg,
        )
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem
    except Exception as exc:
        raise KeyGenerationError(f"RSA key generation failed: {exc}") from exc

def rsa_encrypt(public_pem: bytes, plaintext: bytes, label: Optional[bytes] = None) -> bytes:
    """
    Encrypt data using RSA-OAEP with SHA-256.

    Args:
        public_pem: Public key in PEM format.
        plaintext: Data to encrypt.
        label: Optional OAEP label (bytes).

    Returns:
        Ciphertext bytes.

    Raises:
        RSAError: On failure.
    """
    try:
        public_key = serialization.load_pem_public_key(public_pem)
        ciphertext = public_key.encrypt(
            plaintext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label,
            ),
        )
        return ciphertext
    except Exception as exc:
        raise RSAError(f"RSA encryption failed: {exc}") from exc

def rsa_decrypt(private_pem: bytes, ciphertext: bytes, password: Optional[Union[str, bytes]] = None, label: Optional[bytes] = None) -> bytes:
    """
    Decrypt data using RSA-OAEP with SHA-256.

    Args:
        private_pem: Private key in PEM format (optionally encrypted).
        ciphertext: Data to decrypt.
        password: Optional password to decrypt private key.
        label: Optional OAEP label (bytes) must match encryption if used.

    Returns:
        Plaintext bytes.

    Raises:
        RSAError: On failure.
    """
    try:
        if isinstance(password, str):
            password_bytes = password.encode("utf-8")
        elif isinstance(password, (bytes, bytearray)) or password is None:
            password_bytes = password if password is None else bytes(password)
        else:
            raise RSAError("Password must be str or bytes if provided.")
        private_key = serialization.load_pem_private_key(private_pem, password=password_bytes)
        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label,
            ),
        )
        return plaintext
    except Exception as exc:
        raise RSAError(f"RSA decryption failed: {exc}") from exc

def rsa_sign(private_pem: bytes, data: bytes, password: Optional[Union[str, bytes]] = None) -> bytes:
    """
    Sign data using RSA-PSS with SHA-256.

    Args:
        private_pem: Private key PEM (optionally encrypted).
        data: Message to sign.
        password: Optional password to decrypt private key.

    Returns:
        Signature bytes.

    Raises:
        RSAError: On failure.
    """
    try:
        if isinstance(password, str):
            password_bytes = password.encode("utf-8")
        elif isinstance(password, (bytes, bytearray)) or password is None:
            password_bytes = password if password is None else bytes(password)
        else:
            raise RSAError("Password must be str or bytes if provided.")
        private_key = serialization.load_pem_private_key(private_pem, password=password_bytes)
        signature = private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return signature
    except Exception as exc:
        raise RSAError(f"RSA signing failed: {exc}") from exc

def rsa_verify(public_pem: bytes, data: bytes, signature: bytes) -> bool:
    """
    Verify RSA-PSS SHA-256 signature.

    Args:
        public_pem: Public key PEM.
        data: Original message.
        signature: Signature bytes.

    Returns:
        True if valid, False otherwise.
    """
    try:
        public_key = serialization.load_pem_public_key(public_pem)
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# ----------------------------
# Minimal CLI (optional)
# ----------------------------

def _print_warning():
    msg = (
        "WARNING: Use this tool only for lawful, authorized purposes. "
        "Unauthorized access or misuse may be illegal."
    )
    try:
        import sys
        print(msg, file=sys.stderr)
    except Exception:
        pass

def _parse_args(argv: list[str]) -> tuple[str, dict]:
    """
    Very small argument parser for basic operations.

    Commands:
      - gen-rsa [--size 2048|3072|4096] [--out-priv path] [--out-pub path] [--pw password]
      - enc-file --in path --out path (--key HEX|--pw PASSWORD) [--aad HEX]
      - dec-file --in path --out path (--key HEX|--pw PASSWORD) [--aad HEX]
      - gen-aes [--len 32]

    Returns:
      (command, options_dict)
    """
    import sys
    args = list(argv)
    opts = {}
    if not args:
        return "", {}
    cmd = args.pop(0)
    def pop_val(flag: str, default: Optional[str] = None) -> Optional[str]:
        if flag in args:
            i = args.index(flag)
            try:
                val = args[i + 1]
            except Exception:
                val = None
            # Remove flag and value
            try:
                args.pop(i)  # flag
                val = args.pop(i)  # value now at same index
            except Exception:
                val = None
            return val
        return default
    def flag_present(flag: str) -> bool:
        if flag in args:
            args.remove(flag)
            return True
        return False
    if cmd == "gen-rsa":
        opts["size"] = int(pop_val("--size", "2048"))
        opts["out_priv"] = pop_val("--out-priv", "rsa_private.pem")
        opts["out_pub"] = pop_val("--out-pub", "rsa_public.pem")
        pw = pop_val("--pw", None)
        opts["password"] = pw
    elif cmd == "enc-file":
        opts["in"] = pop_val("--in")
        opts["out"] = pop_val("--out")
        key_hex = pop_val("--key", None)
        pw = pop_val("--pw", None)
        aad_hex = pop_val("--aad", None)
        if key_hex and pw:
            print("Specify only one of --key or --pw.", file=sys.stderr)
            return "", {}
        opts["key"] = bytes.fromhex(key_hex) if key_hex else None
        opts["password"] = pw
        opts["aad"] = bytes.fromhex(aad_hex) if aad_hex else None
    elif cmd == "dec-file":
        opts["in"] = pop_val("--in")
        opts["out"] = pop_val("--out")
        key_hex = pop_val("--key", None)
        pw = pop_val("--pw", None)
        aad_hex = pop_val("--aad", None)
        if key_hex and pw:
            print("Specify only one of --key or --pw.", file=sys.stderr)
            return "", {}
        opts["key"] = bytes.fromhex(key_hex) if key_hex else None
        opts["password"] = pw
        opts["aad"] = bytes.fromhex(aad_hex) if aad_hex else None
    elif cmd == "gen-aes":
        opts["length"] = int(pop_val("--len", "32"))
    else:
        return "", {}
    return cmd, opts

def _cli(argv: list[str]) -> int:
    _print_warning()
    import sys
    try:
        cmd, opts = _parse_args(argv)
        if not cmd:
            print("Usage:", file=sys.stderr)
            print("  gen-rsa [--size 2048|3072|4096] [--out-priv path] [--out-pub path] [--pw password]", file=sys.stderr)
            print("  enc-file --in path --out path (--key HEX|--pw PASSWORD) [--aad HEX]", file=sys.stderr)
            print("  dec-file --in path --out path (--key HEX|--pw PASSWORD) [--aad HEX]", file=sys.stderr)
            print("  gen-aes [--len 32]", file=sys.stderr)
            return 2

        if cmd == "gen-rsa":
            priv_pem, pub_pem = generate_rsa_keypair(key_size=opts["size"], password=opts["password"])
            with open(opts["out_priv"], "wb") as f:
                f.write(priv_pem)
            with open(opts["out_pub"], "wb") as f:
                f.write(pub_pem)
            print(f"RSA keys written: {opts['out_priv']}, {opts['out_pub']}")
            return 0

        if cmd == "enc-file":
            if not opts.get("in") or not opts.get("out"):
                print("enc-file requires --in and --out.", file=sys.stderr)
                return 2
            encrypt_file(
                input_path=opts["in"],
                output_path=opts["out"],
                key=opts["key"],
                password=opts["password"],
                associated_data=opts["aad"],
            )
            print(f"Encrypted: {opts['out']}")
            return 0

        if cmd == "dec-file":
            if not opts.get("in") or not opts.get("out"):
                print("dec-file requires --in and --out.", file=sys.stderr)
                return 2
            decrypt_file(
                input_path=opts["in"],
                output_path=opts["out"],
                key=opts["key"],
                password=opts["password"],
                associated_data=opts["aad"],
            )
            print(f"Decrypted: {opts['out']}")
            return 0

        if cmd == "gen-aes":
            key = generate_aes_key(opts["length"])
            print(key.hex())
            return 0

        print("Unknown command.", file=sys.stderr)
        return 2
    except EncryptionSuiteError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(_cli(sys.argv[1:]))