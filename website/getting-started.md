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

## Create and sign an event

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
