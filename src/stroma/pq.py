"""Experimental fixed-suite PQ primitives; no envelope, discovery or key storage.

Importing this module never imports oqs or loads a native library. Construction
requires an explicit trusted library path. The narrow C binding deliberately
bypasses liboqs-python's import-time installer and global library discovery.
"""
from __future__ import annotations

import ctypes as ct
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from threading import RLock

from .errors import StromaError

WRAPPER_VERSION = "0.16.0.2"
NATIVE_VERSION = "0.16.0"
MAX_MESSAGE_BYTES = 1024 * 1024
_LOCK = RLock()


class PQBackendUnavailable(StromaError, RuntimeError):
    """The explicitly requested optional backend is unavailable or incompatible."""


class PQOperationError(StromaError, RuntimeError):
    """The native backend could not complete an operation."""


@dataclass(frozen=True)
class PQKeyPair:
    """Raw public/secret bytes; callers own secure storage and key lifecycle.

    Python immutable bytes cannot be reliably zeroized. Never log secret_key.
    """

    public_key: bytes
    secret_key: bytes = field(repr=False)


def _bytes(value: bytes, name: str, length: int | None = None) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if length is not None and len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return value


def _message_context(message: bytes, context: bytes) -> None:
    _bytes(message, "message")
    _bytes(context, "context")
    if len(message) > MAX_MESSAGE_BYTES:
        raise ValueError("message exceeds 1 MiB primitive limit")
    if len(context) > 255:
        raise ValueError("ML-DSA context exceeds 255 bytes")


class PQBackend:
    """ML-DSA-44 and ML-KEM-768 only, using liboqs 0.16.0.

    Install stroma-nostr[pq] and provision liboqs separately. library_path must
    be an absolute path to trusted native code, never a value from a peer.
    Calls are synchronous and serialized; async callers should offload them.
    This adapter does not change liboqs's process-global RNG configuration.
    Do not share a process with software that overrides that RNG.
    """

    def __init__(self, library_path: str | Path):
        try:
            version = metadata.version("liboqs-python")
        except metadata.PackageNotFoundError:
            raise PQBackendUnavailable("Install stroma-nostr[pq] to enable PQ support") from None
        if version != WRAPPER_VERSION:
            raise PQBackendUnavailable(f"PQ support requires liboqs-python {WRAPPER_VERSION}")
        path = Path(library_path)
        if not path.is_absolute():
            raise PQBackendUnavailable("liboqs requires an explicit absolute library path")
        try:
            path = path.resolve(strict=True)
            with _LOCK:
                lib = ct.CDLL(str(path))
                lib.OQS_version.argtypes = []
                lib.OQS_version.restype = ct.c_char_p
                if lib.OQS_version() != NATIVE_VERSION.encode():
                    raise PQBackendUnavailable(f"PQ support requires native liboqs {NATIVE_VERSION}")
                p, n = ct.c_void_p, ct.c_size_t
                signatures = {
                    "OQS_SIG_ml_dsa_44_keypair": [p, p],
                    "OQS_SIG_ml_dsa_44_sign_with_ctx_str": [p, ct.POINTER(n), p, n, p, n, p],
                    "OQS_SIG_ml_dsa_44_verify_with_ctx_str": [p, n, p, n, p, n, p],
                    "OQS_KEM_ml_kem_768_keypair": [p, p],
                    "OQS_KEM_ml_kem_768_encaps": [p, p, p],
                    "OQS_KEM_ml_kem_768_decaps": [p, p, p],
                }
                for name, args in signatures.items():
                    fn = getattr(lib, name)
                    fn.argtypes, fn.restype = args, ct.c_int
                lib.OQS_init.argtypes, lib.OQS_init.restype = [], None
                lib.OQS_init()
        except (OSError, AttributeError) as exc:
            raise PQBackendUnavailable(
                "Cannot load the requested liboqs with ML-DSA-44 and ML-KEM-768 enabled"
            ) from exc
        self._lib = lib

    def _call(self, name: str, *args) -> None:
        if getattr(self._lib, name)(*args) != 0:
            raise PQOperationError("PQ native operation failed")

    def _keypair(self, name: str, public_size: int, secret_size: int) -> PQKeyPair:
        public, secret = ct.create_string_buffer(public_size), ct.create_string_buffer(secret_size)
        try:
            with _LOCK:
                self._call(name, public, secret)
            return PQKeyPair(public.raw, secret.raw)
        finally:
            ct.memset(secret, 0, secret_size)

    def generate_signing_keypair(self) -> PQKeyPair:
        return self._keypair("OQS_SIG_ml_dsa_44_keypair", 1312, 2560)

    def generate_kem_keypair(self) -> PQKeyPair:
        return self._keypair("OQS_KEM_ml_kem_768_keypair", 1184, 2400)

    def sign(self, message: bytes, secret_key: bytes, *, context: bytes) -> bytes:
        """Randomized ordinary ML-DSA-44; explicit context, not prehash mode."""
        _message_context(message, context)
        _bytes(secret_key, "secret_key", 2560)
        secret = ct.create_string_buffer(secret_key, 2560)
        signature, size = ct.create_string_buffer(2420), ct.c_size_t()
        try:
            with _LOCK:
                self._call("OQS_SIG_ml_dsa_44_sign_with_ctx_str", signature, ct.byref(size),
                           message, len(message), context, len(context), secret)
            if size.value != 2420:
                raise PQOperationError("Unexpected ML-DSA-44 signature size")
            return signature.raw
        finally:
            ct.memset(secret, 0, 2560)

    def verify(self, message: bytes, signature: bytes, public_key: bytes, *, context: bytes) -> bool:
        """Return False for invalid signatures; reject malformed inputs first."""
        _message_context(message, context)
        _bytes(signature, "signature", 2420)
        _bytes(public_key, "public_key", 1312)
        with _LOCK:
            return self._lib.OQS_SIG_ml_dsa_44_verify_with_ctx_str(
                message, len(message), signature, len(signature), context, len(context), public_key
            ) == 0

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return (encapsulation, shared_secret); apply a protocol KDF before use."""
        _bytes(public_key, "public_key", 1184)
        enc, shared = ct.create_string_buffer(1088), ct.create_string_buffer(32)
        try:
            with _LOCK:
                self._call("OQS_KEM_ml_kem_768_encaps", enc, shared, public_key)
            return enc.raw, shared.raw
        finally:
            ct.memset(shared, 0, 32)

    def decapsulate(self, encapsulation: bytes, secret_key: bytes) -> bytes:
        """Implicit rejection returns a different secret, NOT an authenticity flag.

        Callers must authenticate the enclosing protocol (e.g. AEAD plus signature).
        """
        _bytes(encapsulation, "encapsulation", 1088)
        _bytes(secret_key, "secret_key", 2400)
        secret, shared = ct.create_string_buffer(secret_key, 2400), ct.create_string_buffer(32)
        try:
            with _LOCK:
                self._call("OQS_KEM_ml_kem_768_decaps", shared, encapsulation, secret)
            return shared.raw
        finally:
            ct.memset(secret, 0, 2400)
            ct.memset(shared, 0, 32)
