# Getting Started

## Development installation

Stroma currently requires Python 3.11 through 3.13 and uses Poetry for its
development environment.

```console
git clone https://github.com/trbouma/stroma.git
cd stroma
poetry install --with docs
poetry run pytest
```

## Use the local development package

From another virtual environment:

```console
python -m pip install -e /Users/trbouma/projects/stroma
```

The distribution is named `stroma-nostr`, while Python code imports `stroma`:

```python
from stroma import Event, Keys, NIP44Encrypt
```

The default installation above does not install PQ dependencies or load native
liboqs. Existing classical APIs work without the optional extra.

## Enable optional post quantum support

From a Stroma checkout:

```console
poetry install --extras pq
```

For an application consuming a reviewed Git revision, replace `COMMIT_SHA` with
the full commit to install:

```console
pip install 'stroma-nostr[pq] @ git+https://github.com/trbouma/stroma.git@COMMIT_SHA'
```

This installs the Python PQ dependency, not native liboqs. Provision **liboqs
0.16.0** separately and pass its actual absolute library path to
`stroma.pq.PQBackend`. The pinned Python wrapper is **liboqs-python 0.16.0.2**.
Docker applications can compile the native library during image construction;
Stroma never downloads or compiles it at runtime.

Available primitives are **ML-DSA-44** signing/verification and **ML-KEM-768** key
establishment. The encrypted-envelope API remains a proposal; enabling the extra
does not change NIP-44 encryption or make standard Nostr events post-quantum secure.
See the [backend API, examples and limitations](post-quantum-backend.md).

## Create and sign a classical event

```python
from stroma import Event, Keys

keys = Keys()
event = Event(kind=1, content="hello from Stroma")
event.sign(keys)

assert event.is_valid()
print(event.data())
```

## Encrypt between two keys

```python
from stroma import Keys, NIP44Encrypt

alice = Keys()
bob = Keys()

payload = NIP44Encrypt(alice).encrypt("private payload", bob.public_key_hex())
plaintext = NIP44Encrypt(bob).decrypt(payload, alice.public_key_hex())

assert plaintext == "private payload"
```

## Build the documentation

```console
poetry run mkdocs serve
```

Then open `http://127.0.0.1:8000/`.
