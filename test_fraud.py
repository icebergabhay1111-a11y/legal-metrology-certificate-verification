"""
test_fraud.py - two tests per rule: one where it should stay quiet,
one where it should fire.

Run:  python -m pytest -q

Why both halves matter: a rule that fires on an innocent case is worse
than no rule at all, bc it accuses the wrong person.
"""

from datetime import date, timedelta

import fraud

TODAY = date.today()


def d(days):
    """Shorthand: d(-30) = 30 days ago, as a 'YYYY-MM-DD' string."""
    return (TODAY + timedelta(days=days)).isoformat()


def cert(**kw):
    base = {
        "code": "CERT-0002", "serial_number": "WB-4471",
        "owner_name": "Sharma Traders", "instrument_type": "Weighbridge",
        "verified_on": d(0), "expires_on": d(365),
        "officer_id": 2, "officer_name": "Priya Lab Officer",
        "jurisdiction": "Chennai", "state_code": "TN",
    }
    base.update(kw)
    return base


LMO = {"id": 2, "full_name": "Priya Lab Officer", "jurisdiction": "Chennai",
       "state_code": "TN", "kind": "lmo"}

GATC = {"id": 9, "full_name": "VIT Test Centre", "kind": "gatc",
        "approved_state": "TN", "approved_categories": ["weighbridge", "weight"]}


# ---------------------------------------------------------------- rule 1
def test_duplicate_serial_quiet_when_same_owner():
    old = cert(code="CERT-0001")
    assert fraud.check_duplicate_serial(cert(), [old]) is None


def test_duplicate_serial_fires_on_different_owner():
    old = cert(code="CERT-0001", owner_name="Bharat Fuels")
    msg = fraud.check_duplicate_serial(cert(), [old])
    assert msg is not None and "CERT-0001" in msg


# ---------------------------------------------------------------- rule 2
def test_jurisdiction_quiet_when_officer_in_own_area():
    assert fraud.check_out_of_jurisdiction(cert(), LMO) is None


def test_jurisdiction_fires_when_officer_out_of_area():
    msg = fraud.check_out_of_jurisdiction(cert(jurisdiction="Siliguri"), LMO)
    assert msg is not None and "Siliguri" in msg


def test_gatc_fires_outside_approved_state():
    msg = fraud.check_out_of_jurisdiction(cert(state_code="WB"), GATC)
    assert msg is not None and "TN" in msg


def test_gatc_fires_on_unapproved_category():
    msg = fraud.check_out_of_jurisdiction(
        cert(instrument_type="Storage tank"), GATC)
    assert msg is not None and "Storage tank" in msg


# ---------------------------------------------------------------- rule 3
def test_volume_quiet_under_limit():
    assert fraud.check_improbable_volume(LMO, [cert()] * 10, limit=40) is None


def test_volume_fires_over_limit():
    msg = fraud.check_improbable_volume(LMO, [cert()] * 61, limit=40)
    assert msg is not None and "61" in msg


# ---------------------------------------------------------------- rule 4
def test_lapsed_quiet_when_reverified_after_expiry():
    old = cert(code="CERT-0001", owner_name="Bharat Fuels",
               expires_on=d(-30), verified_on=d(-395))
    new = cert(verified_on=d(-1))          # verified AFTER the old lapsed
    assert fraud.check_lapsed_reregistration(new, [old]) is None


def test_lapsed_fires_when_never_reverified():
    old = cert(code="CERT-0001", owner_name="Bharat Fuels",
               expires_on=d(-30), verified_on=d(-395))
    new = cert(verified_on=d(-60))         # verified BEFORE the old lapsed
    msg = fraud.check_lapsed_reregistration(new, [old])
    assert msg is not None and "without re-verification" in msg


# ---------------------------------------------------------------- all
def test_run_all_clean_case_returns_nothing():
    assert fraud.run_all_checks(cert(), [], LMO, [], 40) == []


def test_run_all_collects_more_than_one_problem():
    old = cert(code="CERT-0001", owner_name="Bharat Fuels")
    problems = fraud.run_all_checks(
        cert(jurisdiction="Siliguri"), [old], LMO, [cert()] * 61, 40)
    assert len(problems) >= 3
