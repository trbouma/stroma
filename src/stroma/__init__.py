"""Stroma: a minimal Nostr wire-format interface for Safebox Acorn."""

from .errors import (
    EncryptionError,
    EventError,
    GiftWrapError,
    KeyError,
    RelayError,
    RelayRejectedError,
    StromaError,
)
from .events import Event, EventTags
from .keys import Keys
from .nip19 import Entities, UnknownEntity
from .nip44 import NIP44Encrypt, calc_padded_len, pad, unpad
from .nip59 import GiftWrap
from .relay import PublishResult, RelayClient, RelayPool
from .signing import BasicKeySigner, Signer

__all__ = [
    "BasicKeySigner",
    "EncryptionError",
    "Entities",
    "Event",
    "EventError",
    "EventTags",
    "GiftWrap",
    "GiftWrapError",
    "KeyError",
    "Keys",
    "NIP44Encrypt",
    "PublishResult",
    "RelayClient",
    "RelayError",
    "RelayPool",
    "RelayRejectedError",
    "Signer",
    "StromaError",
    "UnknownEntity",
    "calc_padded_len",
    "pad",
    "unpad",
]

__version__ = "0.1.0"
