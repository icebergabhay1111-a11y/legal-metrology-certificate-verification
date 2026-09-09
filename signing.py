"""
signing.py - digital signature for certificates. (Ed25519)

Owner: Anikeit (26BDE0124) - branch feat/signing-and-config

WHY THIS EXISTS
A fake paper certificate is easy to print. A fake *signature* is not.
We sign the cert's fields w/ a secret key only our server has. Anyone
can check the signature w/ the public key, but nobody can make a valid
one w/o the secret key. So: print a fake cert -> signature fails -> caught.

Answers the mentor's q: "how to handle fake verification".

KEY HANDLING - important
  - Local dev: key is auto-made and saved to signing_key.pem (gitignored).
  - On Render: set env var SIGNING_KEY to the base64 private key.
    Get that string by running:  python signing.py --print-key
  - If SIGNING_KEY is missing the app still runs; it just makes a
    throwaway key each boot, so old sigs won't verify. That's on purpose
    i.e. the app never crashes just bc a key is missing.
"""

import base64
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

KEY_FILE = "signing_key.pem"

# Fields we sign, in THIS order. Never reorder - if u do, every old
# signature stops verifying.
FIELD_ORDER = (
    "code", "serial_number", "owner_name", "instrument_type",
    "verified_on", "expires_on", "officer_id",
)


def _load_or_make_key():
    """Get the private key. Order: env var -> file -> make a new one."""

    env_key = os.environ.get("SIGNING_KEY", "").strip()
    if env_key:
        raw = base64.b64decode(env_key)
        return Ed25519PrivateKey.from_private_bytes(raw)

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
        # Read-only disk (some hosts). Fine - key just lives in memory.
        pass
    return key


_PRIVATE = _load_or_make_key()
_PUBLIC = _PRIVATE.public_key()


def build_payload(cert):
    """Turn a cert dict into the exact string we sign.

    We join every field w/ '|'. Change ONE character anywhere and the
    signature check fails. That's the whole point.
    """
    return "|".join(str(cert.get(f, "")) for f in FIELD_ORDER)


def sign(cert):
    """Sign a cert dict. Returns a base64 string to store in the DB."""
    sig = _PRIVATE.sign(build_payload(cert).encode("utf-8"))
    return base64.b64encode(sig).decode("ascii")


def verify(cert, signature_b64):
    """True if the signature matches the cert as it is stored right now.

    False if: no signature, junk signature, or ANY field was edited
    after issue.
    """
    if not signature_b64:
        return False
    try:
        _PUBLIC.verify(
            base64.b64decode(signature_b64),
            build_payload(cert).encode("utf-8"),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def public_key_b64():
    """Public key as base64. Safe to publish - it only *checks* sigs."""
    return base64.b64encode(_PUBLIC.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode("ascii")


if __name__ == "__main__":
    import sys
    if "--print-key" in sys.argv:
        raw = _PRIVATE.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        print("Set this as SIGNING_KEY on Render:")
        print(base64.b64encode(raw).decode("ascii"))
    else:
        print("public key:", public_key_b64())
