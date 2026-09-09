import pytest
from fraud import (
    check_duplicate_serial,
    check_out_of_jurisdiction,
    check_improbable_volume,
    check_lapsed_and_reregistered,
    run_all_checks,
)

# Rule 1 Tests: Duplicate serial
def test_duplicate_serial_silent():
    cert = {"serial_number": "WB-4471", "owner_name": "Owner A"}
    existing = [{"serial_number": "WB-4471", "owner_name": "Owner A", "is_live": True, "certificate_id": "CERT-0001"}]
    assert check_duplicate_serial(cert, existing) is None


def test_duplicate_serial_fires():
    cert = {"serial_number": "WB-4471", "owner_name": "Owner B"}
    existing = [{"serial_number": "WB-4471", "owner_name": "Owner A", "is_live": True, "certificate_id": "CERT-0007"}]
    result = check_duplicate_serial(cert, existing)
    assert result == "Serial WB-4471 is already certified to a different owner under CERT-0007."


# Rule 2 Tests: Out of jurisdiction
def test_out_of_jurisdiction_silent():
    cert = {
        "officer_id": "LMO-14",
        "officer_jurisdiction": "Siliguri",
        "instrument_jurisdiction": "Siliguri",
    }
    assert check_out_of_jurisdiction(cert) is None


def test_out_of_jurisdiction_fires():
    cert = {
        "officer_id": "LMO-14",
        "officer_jurisdiction": "Kolkata North",
        "instrument_jurisdiction": "Siliguri",
    }
    result = check_out_of_jurisdiction(cert)
    assert result == "Officer LMO-14 is assigned to Kolkata North; this instrument is in Siliguri."


# Rule 3 Tests: Improbable volume
def test_improbable_volume_silent():
    config = {"max_daily_certificates_per_officer": 40}
    cert = {"officer_id": "LMO-14", "issue_date": "2026-09-04"}
    existing = [{"officer_id": "LMO-14", "issue_date": "2026-09-04"}] * 30
    assert check_improbable_volume(cert, existing, config) is None


def test_improbable_volume_fires():
    config = {"max_daily_certificates_per_officer": 40}
    cert = {"officer_id": "LMO-14", "issue_date": "2026-09-04"}
    existing = [{"officer_id": "LMO-14", "issue_date": "2026-09-04"}] * 60
    result = check_improbable_volume(cert, existing, config)
    assert result == "Officer LMO-14 has issued 61 certificates today; the configured limit is 40."


# Rule 4 Tests: Lapsed and re-registered
def test_lapsed_and_reregistered_silent():
    cert = {
        "serial_number": "FDU-1104",
        "owner_name": "New Owner",
        "is_reverified": True,
    }
    existing = [
        {
            "serial_number": "FDU-1104",
            "owner_name": "Old Owner",
            "is_expired": True,
            "expiry_date": "2026-07-26",
        }
    ]
    assert check_lapsed_and_reregistered(cert, existing) is None


def test_lapsed_and_reregistered_fires():
    cert = {
        "serial_number": "FDU-1104",
        "owner_name": "New Owner",
        "is_reverified": False,
    }
    existing = [
        {
            "serial_number": "FDU-1104",
            "owner_name": "Old Owner",
            "is_expired": True,
            "expiry_date": "2026-07-26",
        }
    ]
    result = check_lapsed_and_reregistered(cert, existing)
    assert result == "Serial FDU-1104 expired on 2026-07-26 and has been re-registered without re-verification."


# Integration Test
def test_run_all_checks():
    config = {"max_daily_certificates_per_officer": 40}
    cert = {
        "serial_number": "WB-4471",
        "owner_name": "Owner B",
        "officer_id": "LMO-14",
        "officer_jurisdiction": "Kolkata North",
        "instrument_jurisdiction": "Siliguri",
        "issue_date": "2026-09-04",
        "is_reverified": False,
    }
    existing = [
        {
            "serial_number": "WB-4471",
            "owner_name": "Owner A",
            "is_live": True,
            "certificate_id": "CERT-0007",
        }
    ]
    issues = run_all_checks(cert, existing, config)
    assert len(issues) == 2