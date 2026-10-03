"""
test_app.py - end-to-end checks on the whole app, named by what they prove.

Run:  python -m pytest -q
Domain results are grouped by their LM- code (see errors.py), so coverage
of every code is visible. Security attacks live in test_security.py.
"""

import datetime

import pytest

import clock
import db
from conftest import (PW, TODAY, issue, issue_code, login, post, q,
                      status_of)


# ---------------------------------------------------------------- accounts
def test_demo_users_exist_after_a_fresh_start(app_client):
    """The Render blocker: a wiped database must still have working logins."""
    assert q("SELECT COUNT(*) FROM users")[0][0] >= 4


def test_passwords_are_never_stored_in_plain_text(app_client):
    for (h,) in q("SELECT password_hash FROM users"):
        assert PW not in h and h.startswith(("pbkdf2:", "scrypt:", "argon2"))


def test_good_password_logs_in(app_client):
    assert login(app_client).status_code == 302


def test_wrong_password_and_unknown_user_get_the_same_answer(app_client):
    a = login(app_client, "lab1", "nope")
    b = login(app_client, "ghost", "nope")
    assert a.status_code == b.status_code == 401
    assert b"Incorrect username or password" in a.data and b"Incorrect username or password" in b.data


def test_logout_needs_a_post(app_client):
    login(app_client)
    assert app_client.get("/logout").status_code == 405
    assert post(app_client, "/logout").status_code == 302
    assert app_client.get("/dashboard").status_code == 302


# ---------------------------------------------------------------- roles (SYS-507)
def test_logged_out_visitor_is_sent_to_login(app_client):
    for path in ("/dashboard", "/issue", "/reminders", "/admin/audit", "/admin/health"):
        assert app_client.get(path).status_code == 302, path


def test_trader_is_refused_every_officer_page(app_client):
    login(app_client, "trader1")
    for path in ("/dashboard", "/issue", "/reminders", "/admin/audit"):
        assert app_client.get(path).status_code == 403, path
    assert issue(app_client).status_code == 403


def test_refused_access_is_logged(app_client):
    login(app_client, "trader1")
    app_client.get("/reminders")
    assert q("SELECT COUNT(*) FROM audit WHERE action = 'access refused'")[0][0] == 1


def test_only_admin_reads_the_audit_log_and_health(app_client):
    login(app_client)
    assert app_client.get("/admin/audit").status_code == 403
    login(app_client, "admin1")
    assert app_client.get("/admin/audit").status_code == 200
    assert app_client.get("/admin/health").status_code == 200


# ---------------------------------------------------------------- status: LM-101 to LM-107
def test_LM101_unknown_certificate_is_not_found(app_client):
    for code in ("SD-2222-2222", "CERT-9999", "CERT-99999999999", "nonsense", "%00"):
        r = app_client.get(f"/verify/{code}")
        assert r.status_code in (404, 301), code


def test_new_certificate_is_valid(app_client):
    login(app_client)
    assert status_of(app_client, issue_code(app_client))[0] == "VALID"


def test_LM102_old_certificate_is_expired_and_names_section_33(app_client):
    login(app_client)
    status, body = status_of(app_client, issue_code(app_client, days_ago=400))
    assert status == "EXPIRED" and "Section 33" in body and "2,000" in body


def test_valid_certificate_shows_no_enforcement_panel(app_client):
    login(app_client)
    assert "Section 33" not in status_of(app_client, issue_code(app_client))[1]


def test_LM103_certificate_near_its_end_is_expiring_soon(app_client):
    login(app_client)
    status, body = status_of(app_client, issue_code(app_client, days_ago=330))
    assert status == "EXPIRING SOON"
    assert "reminded" not in body.lower()          # nothing sends reminders yet


def test_LM104_editing_a_stored_field_breaks_the_signature(app_client):
    """The whole anti-forgery claim rests on this test."""
    login(app_client)
    code = issue_code(app_client)
    assert ">VERIFIED<" in status_of(app_client, code)[1]
    db.run("UPDATE certificates SET owner_name = 'Someone Else' WHERE code = :c", c=code)
    status, body = status_of(app_client, code)
    assert status == "NOT VERIFIED" and ">NOT VERIFIED<" in body


def test_LM104_moving_the_expiry_date_breaks_the_signature(app_client):
    login(app_client)
    code = issue_code(app_client, days_ago=400)
    db.run("UPDATE certificates SET expiry_date = '2099-01-01' WHERE code = :c", c=code)
    assert status_of(app_client, code)[0] == "NOT VERIFIED"


def test_LM105_revoked_certificate_reads_revoked_with_reason(app_client):
    login(app_client)
    code = issue_code(app_client)
    login(app_client, "district1")
    r = post(app_client, f"/revoke/{code}", {"reason": "Issued in error during demo"})
    assert r.status_code == 302
    status, body = status_of(app_client, code)
    assert status == "REVOKED" and "Issued in error during demo" in body
    assert q("SELECT COUNT(*) FROM audit WHERE action = 'certificate revoked'")[0][0] == 1


def test_LM105_lab_officer_and_public_cannot_revoke(app_client):
    login(app_client)
    code = issue_code(app_client)
    assert post(app_client, f"/revoke/{code}", {"reason": "trying it"}).status_code == 403
    post(app_client, "/logout")
    assert post(app_client, f"/revoke/{code}", {"reason": "trying it"}).status_code == 302
    assert status_of(app_client, code)[0] == "VALID"


def test_LM105_revoking_needs_a_reason(app_client):
    login(app_client, "district1")
    code = issue_code(app_client)
    assert post(app_client, f"/revoke/{code}", {"reason": " "}).status_code == 400
    assert status_of(app_client, code)[0] == "VALID"


def test_revoked_certificate_leaves_the_due_lists(app_client):
    login(app_client, "district1")
    code = issue_code(app_client, days_ago=400)
    post(app_client, f"/revoke/{code}", {"reason": "Instrument seized"})
    assert code not in app_client.get("/reminders").get_data(as_text=True)


def test_LM107_unreadable_expiry_is_not_shown_as_valid(app_client):
    login(app_client)
    code = issue_code(app_client)
    db.run("UPDATE certificates SET expiry_date = 'garbage' WHERE code = :c", c=code)
    assert status_of(app_client, code)[0] in ("NOT VERIFIED", "UNREADABLE")


# ---------------------------------------------------------------- codes and search
def test_new_codes_are_random_and_not_sequential(app_client):
    login(app_client)
    a = issue_code(app_client, serial="A-1")
    b = issue_code(app_client, serial="A-2")
    assert a != b and a.startswith("SD-") and b.startswith("SD-")


def test_codes_are_accepted_however_they_are_typed(app_client):
    login(app_client)
    code = issue_code(app_client)
    messy = code.lower().replace("-", " ")
    r = app_client.get(f"/verify?code={messy}")
    assert r.status_code == 302 and r.headers["Location"].endswith(f"/verify/{code}")


def test_serial_search_finds_every_certificate_for_that_serial(app_client):
    login(app_client)
    issue_code(app_client, serial="WB-77", days_ago=400)
    issue_code(app_client, serial="WB-77")
    body = app_client.get("/verify?code=wb-77").get_data(as_text=True)
    assert body.count("/verify/SD-") == 2 and "EXPIRED" in body and "VALID" in body


def test_one_match_goes_straight_to_the_certificate(app_client):
    login(app_client)
    code = issue_code(app_client, serial="ONLY-1")
    r = app_client.get("/verify?code=ONLY-1")
    assert r.status_code == 302 and r.headers["Location"].endswith(code)


def test_empty_search_is_refused(app_client):
    assert app_client.get("/verify?code=").status_code == 400


def test_certificate_can_be_reprinted_by_an_officer(app_client):
    login(app_client)
    code = issue_code(app_client)
    page = app_client.get(f"/certificate/{code}").get_data(as_text=True)
    assert code in page and "data:image/png;base64," in page


def test_qr_carries_the_signed_fields_for_offline_checking(app_client):
    import app1
    import certs
    import signing
    login(app_client)
    code = issue_code(app_client, owner="Ram & Sons (sample)")
    row = certs.find(code)
    text = app1.qr_text(row)
    url, payload = text.split("#")
    assert url.endswith(f"/verify/{code}")
    from urllib.parse import unquote
    parts = [unquote(p) for p in payload.split("|")]
    assert parts[0] == "v1" and parts[3] == "Ram & Sons (sample)" and len(parts) == 10
    fields = dict(zip(signing.FIELD_ORDER, parts[1:8]))
    assert signing.verify(fields, parts[9], parts[8])


def test_keys_json_publishes_only_public_keys(app_client):
    keys = app_client.get("/keys.json").get_json()["keys"]
    import signing
    assert keys[0]["key_id"] == signing.KEY_ID
    assert all(set(k) == {"key_id", "public_key"} for k in keys)


# ---------------------------------------------------------------- issuing: LM-3xx
def test_LM301_future_verification_date_is_refused(app_client):
    login(app_client)
    r = issue(app_client, days_ago=-5)
    assert r.status_code == 400 and b"LM-301" in r.data


def test_LM302_instrument_type_must_belong_to_the_state(app_client):
    login(app_client)
    r = issue(app_client, itype="Spaceship scale")
    assert r.status_code == 400 and b"LM-302" in r.data


def test_LM303_unknown_state_is_refused(app_client):
    login(app_client)
    r = issue(app_client, state="XX")
    assert r.status_code == 400 and b"LM-303" in r.data


def test_LM306_missing_fields_are_shown_by_the_field_and_kept(app_client):
    login(app_client)
    r = issue(app_client, serial="", owner="Kept Owner Name")
    page = r.get_data(as_text=True)
    assert r.status_code == 400 and "LM-306" in page
    assert "Serial number is required" in page and 'value="Kept Owner Name"' in page


def test_LM306_pipe_and_overlong_values_are_refused(app_client):
    login(app_client)
    assert issue(app_client, owner="A | B").status_code == 400
    assert issue(app_client, serial="X" * 41).status_code == 400


def test_there_is_no_expiry_field_on_the_form(app_client):
    """A typed expiry can contradict the period. The field must not exist."""
    login(app_client)
    page = app_client.get("/issue").data
    assert b'name="verification_date"' in page and b'name="expiry_date"' not in page


def test_serial_numbers_are_stored_in_one_form(app_client):
    login(app_client)
    code = issue_code(app_client, serial="  wb  44 71 ")
    assert q("SELECT serial_number FROM certificates WHERE code = :c", c=code) == [("WB 44 71",)]


def test_refreshing_after_issue_cannot_issue_twice(app_client):
    login(app_client)
    r = issue(app_client)
    assert r.status_code == 302                        # Post/Redirect/Get
    app_client.get(r.headers["Location"])
    assert q("SELECT COUNT(*) FROM certificates")[0][0] == 1


# ---------------------------------------------------------------- fraud: LM-2xx
def test_LM201_same_serial_different_owner_raises_an_alert(app_client):
    login(app_client)
    issue(app_client, owner="First Owner")
    issue(app_client, owner="Second Owner")
    assert q("SELECT code FROM fraud_alerts") == [("LM-201",)]


def test_same_serial_same_owner_raises_nothing(app_client):
    login(app_client)
    issue(app_client)
    issue(app_client)
    assert q("SELECT COUNT(*) FROM fraud_alerts")[0][0] == 0


def test_LM202_officer_issuing_outside_their_district_raises_an_alert(app_client):
    """lab1 works in Chennai; an instrument in Madurai should be flagged."""
    login(app_client)
    issue(app_client, place="Madurai")
    assert q("SELECT code FROM fraud_alerts") == [("LM-202",)]


def test_LM207_lapsed_instrument_moved_to_a_new_owner_raises_an_alert(app_client):
    login(app_client)
    issue(app_client, owner="Old Owner", days_ago=500)
    issue(app_client, owner="New Owner", days_ago=500)
    codes = {c for (c,) in q("SELECT code FROM fraud_alerts")}
    assert "LM-207" in codes


def test_fraud_alerts_appear_on_the_dashboard_with_their_code(app_client):
    login(app_client)
    issue(app_client, owner="First Owner")
    issue(app_client, owner="Second Owner")
    assert "LM-201" in app_client.get("/dashboard").get_data(as_text=True)


# ---------------------------------------------------------------- States
def test_due_soon_window_comes_from_the_state():
    """Mizoram's window is 90 days and Tamil Nadu's 60: 80 days left differs."""
    import certs
    today = clock.today()
    in_80_days = today + datetime.timedelta(days=80)
    assert certs.status_on(in_80_days, "MZ", today) == ("EXPIRING SOON", 80)
    assert certs.status_on(in_80_days, "TN", today) == ("VALID", 80)


def test_two_states_can_charge_different_fees():
    import config
    assert config.fee_for("DL", "Weighbridge") != config.fee_for("MZ", "Weighbridge")


def test_every_state_file_loads_and_says_its_fees_are_placeholders():
    import config
    assert len(config.STATES) >= 3 and not config.STATE_ERRORS
    for cfg in config.STATES.values():
        assert "PLACEHOLDER" in cfg.get("fee_source", "").upper(), cfg["state_code"]


def test_SYS503_a_broken_state_file_is_skipped_and_reported(tmp_path, monkeypatch):
    import config
    (tmp_path / "ZZ.json").write_text("{ not json", encoding="utf-8")
    monkeypatch.setattr(config, "STATES_DIR", str(tmp_path))
    errors_before = list(config.STATE_ERRORS)
    assert config._load_states() == {}
    assert "ZZ.json" in config.STATE_ERRORS
    config.STATE_ERRORS[:] = errors_before


def test_officer_form_follows_the_chosen_state(app_client):
    login(app_client, "mz1")
    page = app_client.get("/issue").get_data(as_text=True)
    assert "Aizawl" in page and "Chennai" not in page


# ---------------------------------------------------------------- contacts
def test_every_contact_with_a_number_is_sourced_and_dated():
    """An unsourced number must fail the suite, so it can never be merged."""
    import config
    every = list(config.NATIONAL_CONTACTS)
    for cfg in config.STATES.values():
        every.extend(cfg.get("contacts") or [])
    for entry in every:
        if config.has_details(entry):
            assert config.is_sourced(entry), entry.get("label")
            datetime.datetime.strptime(entry["verified_on"], "%Y-%m-%d")


def test_an_unsourced_contact_is_never_shown(monkeypatch):
    import config
    fake = {"label": "Made up office", "phone": "0000", "source": "", "verified_on": ""}
    monkeypatch.setitem(config.STATES["TN"], "contacts", [fake])
    assert config.contacts_for("TN") == []


def test_help_page_shows_nch_with_its_source(app_client):
    page = app_client.get("/info/help").get_data(as_text=True)
    assert "1915" in page and "consumerhelpline.gov.in" in page and "checked 24 Sep 2026" in page


def test_not_found_page_points_to_reporting_and_helpline(app_client):
    _, body = status_of(app_client, "SD-2222-2222")
    assert "Report this certificate" in body and "1915" in body


# ---------------------------------------------------------------- public reports
def test_a_public_report_is_saved_with_a_reference(app_client):
    r = post(app_client, "/report", {"serial_number": "WB-9", "description": "Looks tampered with"})
    (ref,) = q("SELECT reference FROM reports")[0]
    assert ref.startswith("R-") and ref in r.get_data(as_text=True)


def test_an_empty_report_is_refused(app_client):
    assert post(app_client, "/report", {"serial_number": "", "description": ""}).status_code == 400
    assert q("SELECT COUNT(*) FROM reports")[0][0] == 0


# ---------------------------------------------------------------- audit
def test_actions_are_written_to_the_audit_log(app_client):
    login(app_client)
    issue(app_client)
    actions = {r[0] for r in q("SELECT action FROM audit")}
    assert {"login", "certificate issued"} <= actions


def test_audit_chain_detects_an_edited_entry(app_client):
    import auth
    login(app_client)
    issue(app_client)
    assert auth.check_audit_chain() == (True, None)
    db.run("UPDATE audit SET detail = 'nothing happened' WHERE action = 'certificate issued'")
    intact, bad_row = auth.check_audit_chain()
    assert not intact and bad_row is not None


def test_audit_chain_detects_a_deleted_entry(app_client):
    import auth
    login(app_client)
    issue(app_client)
    issue(app_client, serial="B-2")
    db.run("DELETE FROM audit WHERE action = 'login'")      # an entry in the middle
    assert auth.check_audit_chain()[0] is False


# ---------------------------------------------------------------- production safety
def test_production_refuses_to_start_without_secret_key(monkeypatch):
    """A public default secret would let anyone forge an admin session."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    import importlib
    import sys
    with pytest.raises(RuntimeError):
        if "app1" in sys.modules:
            importlib.reload(sys.modules["app1"])
        else:
            import app1  # noqa: F401


def test_SYS502_production_refuses_to_start_without_signing_key(monkeypatch):
    """A fresh random key would silently turn every certificate NOT VERIFIED."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("SIGNING_KEY", raising=False)
    import importlib
    import signing
    with pytest.raises(RuntimeError, match="SYS-502"):
        importlib.reload(signing)
    monkeypatch.delenv("APP_ENV")
    importlib.reload(signing)


def test_production_creates_no_account_without_its_password(monkeypatch):
    """The demo password in the source must not work on the live site."""
    from conftest import drop_db
    drop_db()
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "test-only")
    monkeypatch.setenv("SIGNING_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    monkeypatch.setenv("PW_LAB", "a-real-password")
    for var in ("PW_TRADER", "PW_DISTRICT", "PW_ADMIN", "PW_MZ"):
        monkeypatch.delenv(var, raising=False)
    import importlib
    import app1
    importlib.reload(app1)
    assert q("SELECT username FROM users") == [("lab1",)]
    monkeypatch.delenv("APP_ENV")
    drop_db()


def test_old_signatures_still_verify_after_the_key_is_rotated(monkeypatch, tmp_path):
    """Rotation: the old public key moves to retired_keys.json; old records keep verifying."""
    import base64
    import importlib
    import json
    import signing
    old_sig, old_kid = signing.sign({"code": "SD-AAAA-AAAA"})
    old_public = signing.public_keys()[0]["public_key"]
    retired = tmp_path / "retired.json"
    retired.write_text(json.dumps([{"public_key": old_public}]))
    monkeypatch.setenv("SIGNING_KEY", base64.b64encode(b"\x01" * 32).decode())
    monkeypatch.setenv("RETIRED_KEYS_FILE", str(retired))
    importlib.reload(signing)
    try:
        assert signing.KEY_ID != old_kid
        assert signing.verify({"code": "SD-AAAA-AAAA"}, old_sig, old_kid)
        assert not signing.verify({"code": "SD-AAAA-AAAB"}, old_sig, old_kid)
    finally:
        monkeypatch.undo()
        importlib.reload(signing)


def test_today_is_india_date_even_on_a_utc_server():
    from datetime import timedelta, timezone
    india_now = datetime.datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)
    assert clock.today() == india_now.date()


# ---------------------------------------------------------------- public pages
def test_every_page_says_it_is_a_prototype_not_a_government_site(app_client):
    for path in ("/", "/report", "/login", "/info/help", "/offline", "/verify/SD-2222-2222"):
        body = app_client.get(path).get_data(as_text=True)
        assert "Not an official Government of India website" in body, path
        assert "Emblem" not in body and "Content owned by" not in body, path


def test_help_and_policy_pages_exist(app_client):
    for page in ("help", "accessibility", "privacy", "terms"):
        assert app_client.get(f"/info/{page}").status_code == 200, page
    assert app_client.get("/info/nothing").status_code == 404


def test_healthz_answers_without_the_database(app_client, monkeypatch):
    """The uptime ping must not wake the free database every 5 minutes."""
    def no_db(*a, **k):
        raise AssertionError("healthz touched the database")
    monkeypatch.setattr(db, "fetch_all", no_db)
    monkeypatch.setattr(db, "fetch_one", no_db)
    r = app_client.get("/healthz")
    assert r.status_code == 200 and r.data == b"ok"


def test_offline_checker_files_are_served(app_client):
    for path in ("/offline", "/sw.js", "/manifest.webmanifest", "/static/js/offline.js", "/static/icon-192.png"):
        assert app_client.get(path).status_code == 200, path


def test_a_database_from_before_this_version_upgrades_and_old_certificates_still_verify(app_client):
    """Laptops and older deployments hold certificates signed as CERT-0001."""
    import signing
    from conftest import drop_db
    drop_db()
    db.upgrade_to_latest("0001")                       # the schema as it was on 25 Sep
    sig, _ = signing.sign({"code": "CERT-0001", "serial_number": "OLD-1", "owner_name": "Old Owner",
                           "instrument_type": "Weighbridge", "verified_on": TODAY.isoformat(),
                           "expires_on": "2099-01-01", "officer_id": 2})
    db.run("INSERT INTO certificates (serial_number, owner_name, instrument_type, verification_date, "
           "expiry_date, officer_id, signature, state_code) VALUES ('OLD-1', 'Old Owner', 'Weighbridge', "
           ":v, '2099-01-01', 2, :s, 'TN')", v=TODAY.isoformat(), s=sig)
    db.run("DROP TABLE alembic_version")              # as if made before migrations existed
    db.upgrade_to_latest()
    assert q("SELECT version_num FROM alembic_version") == [("0005",)]
    assert status_of(app_client, "CERT-0001")[0] == "VALID"
    assert status_of(app_client, "cert-1")[0] == "VALID"


# ---------------------------------------------------------------- test data
def test_walkthrough_seed_makes_the_four_presentation_certificates(app_client):
    import seed_demo
    seed_demo.wipe()
    seed_demo.seed_walkthrough()
    expected = ["VALID", "EXPIRED", "EXPIRING SOON", "VALID"]
    assert [status_of(app_client, c)[0] for c in seed_demo.WALKTHROUGH] == expected
    assert q("SELECT code, certificate_code FROM fraud_alerts") == [("LM-201", "CERT-0004")]


def test_full_seed_lands_in_the_agreed_bands_with_every_fraud_rule(app_client):
    import seed_demo
    seed_demo.wipe()
    seed_demo.seed_full()
    assert seed_demo.report() is True
    owners = {o for (o,) in q("SELECT DISTINCT owner_name FROM certificates")}
    assert all(o.endswith("(sample)") for o in owners)
    oldest_allowed = (TODAY - datetime.timedelta(days=3660)).isoformat()
    dates = [d for (d,) in q("SELECT verification_date FROM certificates")]
    assert max(dates) <= TODAY.isoformat() and min(dates) >= oldest_allowed


def test_old_admin_district_is_cleared_by_migration(app_client):
    """admin1 made by the old code had jurisdiction 'State HQ'; 0004 clears it."""
    import os
    from alembic import command
    from alembic.config import Config
    cfg = Config()
    cfg.set_main_option("script_location", os.path.join(db.HERE, "migrations"))
    command.downgrade(cfg, "0003")                      # back to before the fix
    db.run("UPDATE users SET jurisdiction = 'State HQ' WHERE username = 'admin1'")
    db.upgrade_to_latest()
    assert q("SELECT jurisdiction FROM users WHERE username = 'admin1'") == [("",)]
