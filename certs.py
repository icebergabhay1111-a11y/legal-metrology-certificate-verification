"""
certs.py - certificates: their public codes, their status, and lookups.

The status page, the search, the officer dashboard and the
re-verification list all use these functions, so they cannot disagree.
Each State sets its own "due soon" window in states/XX.json.
"""

import re
import secrets
from datetime import datetime

import clock
import config
import db
import signing

# Public codes look like SD-7K4Q-9XWD: 8 characters from 31 that cannot be
# confused (no 0/O, 1/I/L), about 8.5 x 10^11 combinations, so codes
# cannot be guessed by counting. Certificates issued before this change
# keep their CERT-0001 style code.
CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
NEW_CODE = re.compile(r"^SD-[2-9A-HJKMNP-Z]{4}-[2-9A-HJKMNP-Z]{4}$")
OLD_CODE = re.compile(r"^CERT-\d{1,9}$")

COLUMNS = ("id, code, serial_number, owner_name, instrument_type, verification_date, "
           "expiry_date, instrument_class, max_permissible_error, reverification_months, "
           "officer_name, signature, key_id, state_code, officer_id, jurisdiction, "
           "revoked_at, revoked_by, revoke_reason")


def new_code():
    """A fresh random public code, e.g. 'SD-7K4Q-9XWD'."""
    chars = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    return f"SD-{chars[:4]}-{chars[4:]}"


def normalise_code(text):
    """Accept what people type: lower case, spaces, missing dashes."""
    cleaned = re.sub(r"[^0-9A-Za-z]", "", text or "").upper()
    if cleaned.startswith("SD") and len(cleaned) == 10:
        return f"SD-{cleaned[2:6]}-{cleaned[6:]}"
    if cleaned.startswith("CERT") and cleaned[4:].isdigit():
        return f"CERT-{int(cleaned[4:]):04d}"
    return None


def normalise_serial(text):
    """Serial numbers compare in capitals with single spaces."""
    return " ".join((text or "").split()).upper()


def parse_date(text):
    """'2026-10-02' -> date, or None if the stored text is unreadable."""
    try:
        return datetime.strptime(str(text).strip(), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def status_on(expiry, state_code, today):
    """('EXPIRED', days since) / ('EXPIRING SOON', days left) / ('VALID', days left)."""
    if expiry < today:
        return "EXPIRED", (today - expiry).days
    days_left = (expiry - today).days
    if days_left <= config.reminder_days(state_code):
        return "EXPIRING SOON", days_left
    return "VALID", days_left


def signed_fields(row):
    """The fields that were signed at issue, from a stored row."""
    return {
        "code": row.code, "serial_number": row.serial_number, "owner_name": row.owner_name,
        "instrument_type": row.instrument_type, "verified_on": row.verification_date,
        "expires_on": row.expiry_date, "officer_id": row.officer_id,
    }


def find(code):
    """The stored row for a public code, or None."""
    if not code:
        return None
    return db.fetch_one(f"SELECT {COLUMNS} FROM certificates WHERE code = :c", c=code)


def assess(row, today=None):
    """Everything the status page needs to know about one stored certificate.

    Order matters: a record that fails its signature is NOT VERIFIED whatever
    else it says, because none of its other fields can be trusted. Revocation
    comes next, then the dates.
    """
    today = today or clock.today()
    signature_ok = signing.verify(signed_fields(row), row.signature, row.key_id)
    expiry = parse_date(row.expiry_date)
    days = None
    if not signature_ok:
        status, code = "NOT VERIFIED", "LM-104"
    elif row.revoked_at:
        status, code = "REVOKED", "LM-105"
    elif expiry is None:
        status, code = "UNREADABLE", "LM-107"
    else:
        status, days = status_on(expiry, row.state_code, today)
        code = {"EXPIRED": "LM-102", "EXPIRING SOON": "LM-103"}.get(status)
    return {"status": status, "code": code, "days": days, "signature_ok": signature_ok}


def by_serial(serial, limit=20):
    """Certificates for one serial number, newest first, with today's status."""
    rows = db.fetch_all(
        f"SELECT {COLUMNS} FROM certificates WHERE UPPER(serial_number) = :s "
        "ORDER BY verification_date DESC, id DESC LIMIT :n",
        s=normalise_serial(serial), n=limit)
    return [(row, assess(row)) for row in rows]


def due_and_expired():
    """Officer lists: (due within their State's window, already expired).

    Revoked certificates are left out: they need no re-verification reminder.
    """
    today = clock.today()
    rows = db.fetch_all("""
        SELECT code, serial_number, owner_name, instrument_type, expiry_date, state_code
        FROM certificates
        WHERE revoked_at IS NULL
        ORDER BY expiry_date ASC
    """)
    due, expired = [], []
    for row in rows:
        expiry = parse_date(row.expiry_date)
        if expiry is None:
            continue
        status, days = status_on(expiry, row.state_code, today)
        item = {
            "code": row.code, "serial_number": row.serial_number,
            "owner_name": row.owner_name, "instrument_type": row.instrument_type,
            "expires_on": row.expiry_date, "days": days, "state_code": row.state_code,
        }
        if status == "EXPIRED":
            expired.append(item)
        elif status == "EXPIRING SOON":
            due.append(item)
    return due, expired
