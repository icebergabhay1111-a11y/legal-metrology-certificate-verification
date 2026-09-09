"""
fraud.py - the four checks that catch a faker.

Owner: Krishna (26BDE0134) - branch feat/fraud-rules

Plain Python. No Flask, no DB calls. Each rule gets data in, returns
either None (all good) or a short sentence saying what looks wrong.
That makes them easy to test, and easy for anyone to read.

Answers the mentor's q: "how to catch fakers".

A cert here is just a dict w/ these keys:
    code, serial_number, owner_name, instrument_type,
    verified_on, expires_on, officer_id, officer_name,
    jurisdiction, state_code

An officer is a dict w/:
    id, full_name, jurisdiction, state_code, kind ('lmo' or 'gatc'),
    approved_state, approved_categories (list)
"""

from datetime import date, datetime


def _as_date(text):
    """'2026-09-09' -> date. Junk -> None. Never raises."""
    try:
        return datetime.strptime(str(text).strip(), "%Y-%m-%d").date()
    except (ValueError, TypeError, AttributeError):
        return None


# ============================================================
# RULE 1 - same serial, different owner
# ============================================================

def check_duplicate_serial(new_cert, existing_certs):
    """Same instrument serial already live under a DIFFERENT owner.

    Real-world case this catches: one machine's certificate being
    copied onto another shop's machine.
    """
    serial = (new_cert.get("serial_number") or "").strip().upper()
    owner = (new_cert.get("owner_name") or "").strip().lower()
    today = date.today()

    for old in existing_certs:
        if old.get("code") == new_cert.get("code"):
            continue                                    # itself, skip
        if (old.get("serial_number") or "").strip().upper() != serial:
            continue
        if (old.get("owner_name") or "").strip().lower() == owner:
            continue                                    # same owner, fine
        expires = _as_date(old.get("expires_on"))
        if expires and expires >= today:                # still live
            return (f"Serial {serial} is already certified to a different "
                    f"owner under {old.get('code')}.")
    return None


# ============================================================
# RULE 2 - issued outside the issuer's patch
# ============================================================

def check_out_of_jurisdiction(new_cert, officer):
    """Officer working outside their area, or a GATC outside its State.

    The GATC half is not our invention. PIB release 2266230 of
    27 May 2026 says a GATC may verify only inside the State/UT it was
    approved for. Act s.24(3) says who notifies a GATC.
    """
    if officer.get("kind") == "gatc":
        approved_state = (officer.get("approved_state") or "").upper()
        cert_state = (new_cert.get("state_code") or "").upper()
        if approved_state and cert_state and approved_state != cert_state:
            return (f"Test centre {officer.get('full_name')} is approved for "
                    f"{approved_state} only; this instrument is in {cert_state}.")

        cats = [c.strip().lower() for c in officer.get("approved_categories", [])]
        itype = (new_cert.get("instrument_type") or "").strip().lower()
        if cats and itype and itype not in cats:
            return (f"Test centre {officer.get('full_name')} is not approved "
                    f"for {new_cert.get('instrument_type')}.")
        return None

    # Ordinary Legal Metrology Officer - just check the area.
    off_area = (officer.get("jurisdiction") or "").strip().lower()
    cert_area = (new_cert.get("jurisdiction") or "").strip().lower()
    if off_area and cert_area and off_area != cert_area:
        return (f"Officer {officer.get('full_name')} is assigned to "
                f"{officer.get('jurisdiction')}; this instrument is in "
                f"{new_cert.get('jurisdiction')}.")
    return None


# ============================================================
# RULE 3 - too many in one day
# ============================================================

def check_improbable_volume(officer, certs_today, limit=40):
    """One officer issuing more in a day than is physically possible.

    limit comes from the State config file, NOT hard-coded law.
    """
    n = len(certs_today)
    if n > limit:
        return (f"Officer {officer.get('full_name')} has issued {n} "
                f"certificates today; the configured limit is {limit}.")
    return None


# ============================================================
# RULE 4 - lapsed, then quietly re-registered
# ============================================================

def check_lapsed_reregistration(new_cert, existing_certs):
    """Expired instrument re-registered to a new owner, never re-verified.

    i.e. somebody tries to wash an expired machine clean by moving it
    to a new name instead of getting it re-verified.
    """
    serial = (new_cert.get("serial_number") or "").strip().upper()
    owner = (new_cert.get("owner_name") or "").strip().lower()
    new_verified = _as_date(new_cert.get("verified_on"))
    today = date.today()

    for old in existing_certs:
        if old.get("code") == new_cert.get("code"):
            continue
        if (old.get("serial_number") or "").strip().upper() != serial:
            continue
        if (old.get("owner_name") or "").strip().lower() == owner:
            continue
        expires = _as_date(old.get("expires_on"))
        if not expires or expires >= today:
            continue                                    # not expired, skip
        # It IS expired and the owner changed. Only OK if the new cert
        # was actually verified after the old one lapsed.
        if new_verified is None or new_verified <= expires:
            return (f"Serial {serial} expired on {expires.isoformat()} and has "
                    f"been re-registered without re-verification.")
    return None


# ============================================================
# RUN THEM ALL
# ============================================================

def run_all_checks(new_cert, existing_certs, officer, certs_today=None,
                   limit=40):
    """Run every rule. Returns a list of problems, [] if clean."""
    certs_today = certs_today or []
    found = [
        check_duplicate_serial(new_cert, existing_certs),
        check_out_of_jurisdiction(new_cert, officer),
        check_improbable_volume(officer, certs_today, limit),
        check_lapsed_reregistration(new_cert, existing_certs),
    ]
    return [f for f in found if f]
