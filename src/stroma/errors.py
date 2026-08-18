"""Stable exception types exposed by Stroma."""


class StromaError(Exception):
    """Base class for Stroma failures."""


class KeyError(StromaError, ValueError):
    """A key is malformed or unsuitable for the requested operation."""


class EventError(StromaError, ValueError):
    """An event is malformed or fails validation."""


class EncryptionError(StromaError, ValueError):
    """An encrypted payload is malformed, unsupported, or unauthentic."""


class GiftWrapError(StromaError, ValueError):
    """A NIP-59 envelope is malformed or addressed to another key."""


class RelayError(StromaError, RuntimeError):
    """A relay operation could not be completed."""


class RelayRejectedError(RelayError):
    """A relay explicitly rejected a published event."""
