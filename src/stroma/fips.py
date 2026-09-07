"""Deterministic FIPS addressing derived from Nostr public keys."""

from __future__ import annotations

import hashlib
import ipaddress

from .keys import Keys


def fips_ipv6_address(public_key: str | Keys) -> str:
    """Return the canonical FIPS ULA derived from an x-only public key.

    FIPS hashes the 32-byte public key with SHA-256, takes the first 15 hash
    bytes, and prepends the ``0xfd`` ULA prefix byte.
    """

    public_hex = (
        public_key.public_key_hex()
        if isinstance(public_key, Keys)
        else Keys(pub_k=public_key).public_key_hex()
    )
    digest = hashlib.sha256(bytes.fromhex(public_hex)).digest()
    return str(ipaddress.IPv6Address(bytes([0xFD]) + digest[:15]))
