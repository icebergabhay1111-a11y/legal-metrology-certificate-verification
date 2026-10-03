"""
signing.py - Ed25519 signatures on certificates, with key ids.

WHAT A SIGNATURE PROVES, AND WHAT IT DOES NOT
The server signs the certificate's fields at the moment of issue. Later,
the status page re-checks the signature against the fields as they are
stored now, so a record edited in the database without the key reads
NOT VERIFIED. The QR code also carries the fields and the signature, so a
phone holding our public key can check a printed certificate offline.
It does not prove the instrument is accurate, and it does not stop
someone with the private key (i.e. the server itself) from signing.

KEYS
  SIGNING_KEY      base64 of the 32-byte private key. Required when
                   APP_ENV=production: the app refuses to start without it,
                   because a fresh random key would silently make every
                   existing certificate read NOT VERIFIED.
  key id           first 16 hex characters of SHA-256 of the public key.
                   Stored beside every signature.
  retired_keys.json  public keys of keys no longer used to sign, by key id.
                   Rotating the key = move the old public key here, set the
                   new SIGNING_KEY. Old certificates keep verifying.
  Locally, a key is made once and kept in signing_key.pem (gitignored).

Get the value for Render with:  python signing.py --print-key
"""

import base64
import hashlib
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

KEY_FILE = "signing_key.pem"
RETIRED_FILE = os.environ.get("RETIRED_KEYS_FILE", "retired_keys.json")

# Fields we sign, in THIS order. Never reorder - every old signature
# would stop verifying.
FIELD_ORDER = (
    "code", "serial_number", "owner_name", "instrument_type",
    "verified_on", "expires_on", "officer_id",
)


class SigningKeyMissing(RuntimeError):
    """SYS-502: production started without SIGNING_KEY."""


def _load_private_key():
    """Private key from SIGNING_KEY, else the local file, else a new local one."""
    env_key = os.environ.get("SIGNING_KEY", "").strip()
    if env_key:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(env_key))
    if os.environ.get("APP_ENV") == "production":
        raise SigningKeyMissing("SYS-502: SIGNING_KEY is not set. Refusing to start in production.")
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = Ed25519PrivateKey.generate()
    try:
        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
    except OSError:
        pass        # read-only disk: the key lives in memory for this run
    return key


def raw_public(public_key):
    """32 raw bytes of a public key."""
    return public_key.public_bytes(encoding=serialization.Encoding.Raw,
                                   format=serialization.PublicFormat.Raw)


def key_id_for(public_key):
    """Short, stable name for a public key."""
    return hashlib.sha256(raw_public(public_key)).hexdigest()[:16]


def _load_retired():
    """{key id: public key} for keys that verify old certificates but sign nothing."""
    out = {}
    try:
        with open(RETIRED_FILE, encoding="utf-8") as f:
            entries = json.load(f)
    except (OSError, ValueError):
        return out
    for entry in entries:
        try:
            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(entry["public_key"]))
        except (KeyError, ValueError, TypeError):
            continue
        out[key_id_for(key)] = key
    return out


_PRIVATE = _load_private_key()
_PUBLIC = _PRIVATE.public_key()
KEY_ID = key_id_for(_PUBLIC)
KEYRING = {**_load_retired(), KEY_ID: _PUBLIC}


def build_payload(cert):
    """The exact text that is signed: the fields joined with '|'."""
    return "|".join(str(cert.get(f, "")) for f in FIELD_ORDER)


def sign(cert):
    """Sign a certificate dict. Returns (base64 signature, key id)."""
    sig = _PRIVATE.sign(build_payload(cert).encode("utf-8"))
    return base64.b64encode(sig).decode("ascii"), KEY_ID


def verify(cert, signature_b64, key_id=None):
    """True only if the signature matches the fields exactly as given.

    Rows signed before key ids existed have key_id None; they were signed
    with the current key, so that is the one tried.
    """
    if not signature_b64:
        return False
    public = KEYRING.get(key_id or KEY_ID)
    if public is None:
        return False
    try:
        public.verify(base64.b64decode(signature_b64), build_payload(cert).encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def public_keys():
    """[{key_id, public_key}] for every key that can verify, current first."""
    out = [{"key_id": KEY_ID, "public_key": base64.b64encode(raw_public(_PUBLIC)).decode()}]
    for kid, key in KEYRING.items():
        if kid != KEY_ID:
            out.append({"key_id": kid, "public_key": base64.b64encode(raw_public(key)).decode()})
    return out


if __name__ == "__main__":
    if "--print-key" in sys.argv:
        raw = _PRIVATE.private_bytes(encoding=serialization.Encoding.Raw,
                                     format=serialization.PrivateFormat.Raw,
                                     encryption_algorithm=serialization.NoEncryption())
        print("Set this as SIGNING_KEY on Render (keep it secret):")
        print(base64.b64encode(raw).decode("ascii"))
    print("key id:    ", KEY_ID)
    print("public key:", public_keys()[0]["public_key"])
