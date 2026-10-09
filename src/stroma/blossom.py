"""Bounded Blossom retrieval and replicated storage of exact bytes."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import math
import re
import socket
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Iterable, Literal

import aiohttp
from yarl import URL

from .errors import StromaError
from .events import Event
from .keys import Keys
from .signing import BasicKeySigner, Signer

StorageRequirement = Literal["any", "half", "majority", "all"]


@dataclass(frozen=True)
class BlossomOutcome:
    server: str
    status: Literal["confirmed", "rejected", "unconfirmed", "failed"]
    message: str = ""


class BlossomError(StromaError):
    def __init__(self, message: str, outcomes: Iterable[BlossomOutcome] = ()):
        super().__init__(message)
        self.outcomes = tuple(outcomes)


@dataclass(frozen=True)
class BlossomRetrievalResult:
    digest: str
    content: bytes
    server: str
    media_type: str


@dataclass(frozen=True)
class BlossomStoreResult:
    digest: str
    require: StorageRequirement
    required: int
    outcomes: tuple[BlossomOutcome, ...]

    @property
    def confirmed_servers(self) -> tuple[str, ...]:
        return tuple(item.server for item in self.outcomes if item.status == "confirmed")

    @property
    def ok(self) -> bool:
        return len(self.confirmed_servers) >= self.required


def storage_threshold(count: int, require: StorageRequirement = "any") -> int:
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("At least one unique server is required")
    if require not in {"any", "half", "majority", "all"}:
        raise ValueError("require must be any, half, majority, or all")
    return {"any": 1, "half": (count + 1) // 2, "majority": count // 2 + 1, "all": count}[require]


def _public_address(host: str) -> bool:
    address = ipaddress.ip_address(host)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


class _PublicResolver(aiohttp.abc.AbstractResolver):
    def __init__(self):
        self.resolver = aiohttp.resolver.ThreadedResolver()

    async def resolve(self, host, port=0, family=socket.AF_INET):
        addresses = await self.resolver.resolve(host, port, family)
        if not addresses or any(not _public_address(item["host"]) for item in addresses):
            raise OSError("Blossom destination must resolve only to public addresses")
        # The connector uses these checked addresses, without a second DNS lookup.
        return addresses

    async def close(self):
        await self.resolver.close()


class BlossomPool:
    def __init__(
        self, servers: Iterable[str], *, timeout: float = 10,
        operation_timeout: float = 60, max_bytes: int = 25 * 1024 * 1024,
        concurrency: int = 4, max_servers: int = 32,
        allow_private: bool = False, allow_http: bool = False,
    ):
        if not all(math.isfinite(value) and value > 0 for value in (timeout, operation_timeout)):
            raise ValueError("Timeouts must be finite and positive")
        for value in (max_bytes, concurrency, max_servers):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError("Resource limits must be positive integers")
        self.timeout, self.operation_timeout = timeout, operation_timeout
        self.max_bytes, self.concurrency, self.max_servers = max_bytes, concurrency, max_servers
        self.allow_private, self.allow_http = allow_private, allow_http
        self.servers = self._servers(servers)
        if not self.servers:
            raise ValueError("At least one Blossom server is required")

    def _server(self, value: str) -> str:
        if not isinstance(value, str) or any(ord(char) <= 32 for char in value):
            raise ValueError("Invalid Blossom server URL")
        url = URL(value)
        if (url.scheme not in ({"https", "http"} if self.allow_http else {"https"})
                or not url.host or url.user is not None or url.password is not None
                or url.query_string or url.fragment or url.path not in {"", "/"}):
            raise ValueError("Blossom servers must be HTTPS origins without credentials, paths, query, or fragment")
        try:
            address = ipaddress.ip_address(url.host)
        except ValueError:
            address = None
        if address is not None and not self.allow_private and not _public_address(str(address)):
            raise ValueError("Private Blossom destinations are disabled")
        return str(url.origin()).rstrip("/")

    def _servers(self, values: Iterable[str]) -> tuple[str, ...]:
        if isinstance(values, str):
            values = [values]
        servers = []
        seen = set()
        for value in values:
            server = self._server(value)
            if server not in seen:
                if len(servers) >= self.max_servers:
                    raise ValueError("Too many unique Blossom server origins")
                seen.add(server)
                servers.append(server)
        return tuple(servers)

    @asynccontextmanager
    async def _session(self):
        resolver = None if self.allow_private else _PublicResolver()
        connector = aiohttp.TCPConnector(resolver=resolver, limit=self.concurrency, use_dns_cache=False)
        try:
            async with aiohttp.ClientSession(
                connector=connector, timeout=aiohttp.ClientTimeout(total=self.timeout),
                trust_env=False, auto_decompress=False, cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                yield session
        finally:
            if resolver is not None:
                await resolver.close()

    async def _get(self, session, server: str, digest: str) -> BlossomRetrievalResult:
        async with session.get(f"{server}/{digest}", allow_redirects=False) as response:
            if response.status != 200:
                raise BlossomError(f"Retrieval returned HTTP {response.status}")
            if response.content_length is not None and response.content_length > self.max_bytes:
                raise BlossomError("Blob exceeds the size limit")
            content = bytearray()
            async for chunk in response.content.iter_chunked(64 * 1024):
                content.extend(chunk)
                if len(content) > self.max_bytes:
                    raise BlossomError("Blob exceeds the size limit")
            if hashlib.sha256(content).hexdigest() != digest:
                raise BlossomError("Blob SHA-256 mismatch")
            return BlossomRetrievalResult(digest, bytes(content), server, response.headers.get("Content-Type", "application/octet-stream"))

    async def retrieve(self, digest: str, *, hints: Iterable[str] = ()) -> BlossomRetrievalResult:
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise ValueError("digest must be a SHA-256 hex string")
        digest = digest.lower()
        servers = self._servers((*self.servers, *self._servers(hints)))
        outcomes = {}
        semaphore = asyncio.Semaphore(self.concurrency)
        async with self._session() as session:
            async def attempt(server):
                async with semaphore:
                    try:
                        return await self._get(session, server, digest)
                    except (aiohttp.ClientError, OSError, TimeoutError, BlossomError) as exc:
                        outcomes[server] = BlossomOutcome(server, "failed", str(exc) or "Request timed out")
                        return None

            tasks = [asyncio.create_task(attempt(server)) for server in servers]
            try:
                async with asyncio.timeout(self.operation_timeout):
                    for task in asyncio.as_completed(tasks):
                        result = await task
                        if result is not None:
                            return result
            except TimeoutError:
                pass
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        raise BlossomError("No verified Blossom copy was retrieved", [
            outcomes.get(server, BlossomOutcome(server, "failed", "Operation deadline exceeded")) for server in servers
        ])

    async def _authorization(self, signer: Signer, digest: str, server: str) -> str:
        event = Event(kind=24242, content="Upload exact bytes to Blossom", tags=[
            ["t", "upload"], ["x", digest], ["server", URL(server).host.lower()],
            ["expiration", str(int(time.time()) + 300)],
        ])
        event.pub_key = await signer.get_public_key()
        await signer.sign_event(event)
        if not event.is_valid():
            raise BlossomError("Signer did not produce a valid authorization event")
        return "Nostr " + base64.urlsafe_b64encode(json.dumps(event.data(), separators=(",", ":")).encode()).decode().rstrip("=")

    async def store(
        self, content: bytes, *, signer: Signer | Keys,
        require: StorageRequirement = "any", media_type: str = "application/octet-stream",
    ) -> BlossomStoreResult:
        required = storage_threshold(len(self.servers), require)
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        if len(content) > self.max_bytes:
            raise ValueError("Blob exceeds the size limit")
        if not media_type or any(ord(char) < 32 or ord(char) == 127 for char in media_type):
            raise ValueError("Invalid media type")
        signer = BasicKeySigner(signer) if isinstance(signer, Keys) else signer
        digest = hashlib.sha256(content).hexdigest()
        outcomes = {}
        semaphore = asyncio.Semaphore(self.concurrency)
        # Remote signers need not support concurrent requests.
        signing_lock = asyncio.Lock()
        async with self._session() as session:
            async def attempt(server):
                async with semaphore:
                    try:
                        await self._get(session, server, digest)
                        outcomes[server] = BlossomOutcome(server, "confirmed", "Already available and verified")
                        return
                    except (aiohttp.ClientError, OSError, TimeoutError, BlossomError):
                        pass
                    try:
                        async with signing_lock:
                            authorization = await self._authorization(signer, digest, server)
                    except Exception:
                        outcomes[server] = BlossomOutcome(server, "unconfirmed", "Upload authorization failed")
                        return
                    rejected = False
                    detail = "Upload response not confirmed"
                    try:
                        async with session.put(f"{server}/upload", data=content, allow_redirects=False, headers={
                            "Authorization": authorization, "Content-Type": media_type,
                            "Content-Length": str(len(content)), "X-SHA-256": digest,
                        }) as response:
                            rejected = 400 <= response.status < 500
                            detail = f"Upload returned HTTP {response.status}"
                            # The descriptor is not evidence of stored bytes; verify via GET.
                    except (aiohttp.ClientError, OSError, TimeoutError):
                        pass
                    try:
                        await self._get(session, server, digest)
                        outcomes[server] = BlossomOutcome(server, "confirmed", "Retrieved and SHA-256 verified")
                    except (aiohttp.ClientError, OSError, TimeoutError, BlossomError):
                        outcomes[server] = BlossomOutcome(server, "rejected" if rejected else "unconfirmed", detail)

            tasks = [asyncio.create_task(attempt(server)) for server in self.servers]
            try:
                async with asyncio.timeout(self.operation_timeout):
                    await asyncio.gather(*tasks)
            except TimeoutError:
                pass
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        return BlossomStoreResult(digest, require, required, tuple(
            outcomes.get(server, BlossomOutcome(server, "unconfirmed", "Operation deadline exceeded; storage may have occurred"))
            for server in self.servers
        ))
