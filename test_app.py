"""
test_app.py - end-to-end checks on the whole app.

Run:  python -m pytest -q

These are Vaibhavi's acceptance checks, written as code so they can be
re-run in 2 seconds after every change instead of clicked by hand.
Each test name says what it proves.
"""

import datetime
import os
import re
import time

import pytest

import db

DB = "certificates.db"
TODAY = datetime.date.today()
PW = "sahidaam2026"


def q(sql):
    """Run a read-only query through db.py, so it works on SQLite and PostgreSQL."""
    return [tuple(row) for row in db.fetch_all(sql)]


def drop_db():
    """Start every test from an empty database.

    PostgreSQL (CI sets DATABASE_URL): drop every table.
    SQLite: delete the file. Retries for about a second bc Windows can hold
    the handle for a moment after the last connection closes.
    """
    if os.environ.get("APP_ENV") == "production":
        raise RuntimeError("refusing to wipe a production database")
    if db.engine.dialect.name == "postgresql":
        db.run("DROP TABLE IF EXISTS certificates, fraud_alerts, users, audit, "
               "reports, alembic_version CASCADE")
        return
    for attempt in range(5):
        if not os.path.exists(DB):
            return
        try:
            os.remove(DB)
            return
        except PermissionError:
            time.sleep(0.2)
    raise RuntimeError(
        f"could not delete {DB} - something still has it open. "
        "Close DB Browser for SQLite, or stop the running app, and try again.")


@pytest.fixture()
def app_client():
    """Fresh DB + a test client, for every single test."""
    drop_db()
    import importlib
    import app1
    importlib.reload(app1)
    app1.app.config["TESTING"] = True
    yield app1.app.test_client()
    drop_db()


def login(c, user="lab1"):
    return c.post("/login", data={"username": user, "password": PW})


def issue(c, serial="WB-4471", itype="Weighbridge", days_ago=0,
          state="TN", owner="Sharma Traders"):
    return c.post("/submit", data={
        "serial_number": serial, "owner_name": owner, "instrument_type": itype,
        "instrument_class": "Class III", "max_permissible_error": "20 kg",
        "verification_date": (TODAY - datetime.timedelta(days=days_ago)).isoformat(),
        "state_code": state,
    })


def status_of(c, code):
    body = c.get(f"/verify/{code}").data.decode()
    m = re.search(r'class="status \w+">(.*?)</div>', body, re.S)
    return (m.group(1).strip() if m else "NONE"), body


# ---------------------------------------------------------------- accounts
def test_demo_users_exist_after_a_fresh_start(app_client):
    """The Render blocker. A wiped DB must still have working logins."""
    assert q("SELECT COUNT(*) FROM users")[0][0] >= 4


def test_passwords_are_never_stored_in_plain_text(app_client):
    for (h,) in q("SELECT password_hash FROM users"):
        assert PW not in h
        assert h.startswith(("pbkdf2:", "scrypt:", "argon2"))


def test_good_password_logs_in(app_client):
    assert login(app_client).status_code == 302


def test_wrong_password_is_refused(app_client):
    r = app_client.post("/login", data={"username": "lab1", "password": "nope"})
    assert r.status_code == 401


def test_unknown_user_gets_the_same_message_as_wrong_password(app_client):
    r = app_client.post("/login",
                        data={"username": "ghost", "password": "nope"})
    assert r.status_code == 401
    assert b"Incorrect username or password" in r.data


# ---------------------------------------------------------------- roles
def test_logged_out_visitor_cannot_reach_the_dashboard(app_client):
    assert app_client.get("/dashboard").status_code == 302


def test_trader_cannot_reach_the_dashboard(app_client):
    login(app_client, "trader1")
    assert app_client.get("/dashboard").status_code == 403


def test_trader_cannot_reach_the_reminders_page(app_client):
    """This one was a real hole - /reminders had no guard at all."""
    login(app_client, "trader1")
    assert app_client.get("/reminders").status_code == 403


def test_trader_cannot_issue_a_certificate(app_client):
    login(app_client, "trader1")
    assert issue(app_client).status_code == 403


def test_lab_officer_cannot_read_the_audit_log(app_client):
    login(app_client)
    assert app_client.get("/admin/audit").status_code == 403


def test_admin_can_read_the_audit_log(app_client):
    login(app_client, "admin1")
    assert app_client.get("/admin/audit").status_code == 200


# ---------------------------------------------------------------- expiry
def test_new_certificate_is_valid(app_client):
    login(app_client); issue(app_client)
    assert status_of(app_client, "CERT-0001")[0] == "VALID"


def test_old_certificate_is_expired(app_client):
    login(app_client)
    issue(app_client, serial="FDU-1", itype="Fuel dispensing unit", days_ago=400)
    assert status_of(app_client, "CERT-0001")[0] == "EXPIRED"


def test_certificate_near_the_end_says_expiring_soon(app_client):
    login(app_client)
    issue(app_client, serial="FDU-2", itype="Fuel dispensing unit", days_ago=335)
    assert status_of(app_client, "CERT-0001")[0] == "EXPIRING SOON"


def test_unknown_certificate_says_not_found(app_client):
    assert status_of(app_client, "CERT-9999")[0] == "NOT FOUND"


def test_nonsense_certificate_id_says_not_found(app_client):
    assert status_of(app_client, "banana")[0] == "NOT FOUND"


def test_future_verification_date_is_refused(app_client):
    login(app_client)
    r = app_client.post("/submit", data={
        "serial_number": "X", "owner_name": "Y", "instrument_type": "Weight",
        "verification_date": (TODAY + datetime.timedelta(days=5)).isoformat()})
    assert r.status_code == 400


def test_there_is_no_expiry_field_on_the_form(app_client):
    """A typed expiry can contradict the period. The field must not exist."""
    assert b'name="expiry_date"' not in app_client.get("/").data


# ---------------------------------------------------------------- signature
def test_a_fresh_certificate_has_a_valid_signature(app_client):
    login(app_client); issue(app_client)
    assert ">VERIFIED<" in status_of(app_client, "CERT-0001")[1]


def test_editing_the_database_breaks_the_signature(app_client):
    """The whole anti-forgery claim rests on this one test."""
    login(app_client); issue(app_client)
    db.run("UPDATE certificates SET owner_name = 'Someone Else' WHERE id = 1")
    assert ">NOT VERIFIED<" in status_of(app_client, "CERT-0001")[1]


# ---------------------------------------------------------------- enforcement
def test_expired_certificate_shows_the_section_and_penalty(app_client):
    login(app_client)
    issue(app_client, serial="FDU-1", itype="Fuel dispensing unit", days_ago=400)
    body = status_of(app_client, "CERT-0001")[1]
    assert "Section 33" in body and "2,000" in body


def test_valid_certificate_shows_no_enforcement_panel(app_client):
    login(app_client); issue(app_client)
    assert "Section 33" not in status_of(app_client, "CERT-0001")[1]


# ---------------------------------------------------------------- fraud
def test_same_serial_different_owner_raises_an_alert(app_client):
    login(app_client)
    issue(app_client, serial="WB-1", owner="Sharma Traders")
    issue(app_client, serial="WB-1", owner="Bharat Fuels")
    assert q("SELECT COUNT(*) FROM fraud_alerts")[0][0] >= 1


def test_same_serial_same_owner_raises_nothing(app_client):
    login(app_client)
    issue(app_client, serial="WB-1", owner="Sharma Traders")
    issue(app_client, serial="WB-1", owner="Sharma Traders")
    assert q("SELECT COUNT(*) FROM fraud_alerts")[0][0] == 0


# ---------------------------------------------------------------- states
def test_two_states_use_different_reminder_windows(app_client):
    import config
    assert config.reminder_days("MZ") != config.reminder_days("TN")


def test_two_states_can_charge_different_fees(app_client):
    import config
    assert config.fee_for("DL", "Weighbridge") != config.fee_for("MZ", "Weighbridge")


def test_every_state_file_loads(app_client):
    import config
    assert len(config.STATES) >= 3


# ---------------------------------------------------------------- public
def test_anyone_can_open_the_report_form(app_client):
    assert app_client.get("/report").status_code == 200


def test_a_public_report_is_saved(app_client):
    app_client.post("/report", data={"serial_number": "WB-9",
                                     "description": "Looks tampered with"})
    assert q("SELECT COUNT(*) FROM reports")[0][0] == 1


def test_an_empty_report_is_refused(app_client):
    app_client.post("/report", data={"serial_number": "", "description": ""})
    assert q("SELECT COUNT(*) FROM reports")[0][0] == 0


# ---------------------------------------------------------------- audit
def test_actions_are_written_to_the_audit_log(app_client):
    login(app_client); issue(app_client)
    actions = {r[0] for r in q("SELECT action FROM audit")}
    assert "login" in actions


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


def test_production_creates_no_account_without_its_password(monkeypatch):
    """The demo password in the source must not work on the live site."""
    drop_db()
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "test-only")
    monkeypatch.setenv("PW_LAB", "a-real-password")
    for var in ("PW_TRADER", "PW_DISTRICT", "PW_ADMIN", "PW_MZ"):
        monkeypatch.delenv(var, raising=False)
    import importlib
    import app1
    importlib.reload(app1)
    assert q("SELECT username FROM users") == [("lab1",)]
    monkeypatch.delenv("APP_ENV")
    drop_db()


def test_login_never_redirects_to_another_website(app_client):
    """?next= pointing off-site would let a phishing link borrow our login page."""
    for bad in ("https://evil.example", "//evil.example", "/\\evil.example"):
        r = app_client.post(f"/login?next={bad}", data={"username": "lab1", "password": PW})
        assert r.headers["Location"].endswith("/dashboard")
    r = app_client.post("/login?next=/reminders", data={"username": "lab1", "password": PW})
    assert r.headers["Location"].endswith("/reminders")


def test_huge_certificate_number_is_not_found_not_a_crash(app_client):
    """A number too big for the database column must read NOT FOUND, not error 500."""
    r = app_client.get("/verify/CERT-99999999999")
    assert r.status_code == 200 and "NOT FOUND" in r.get_data(as_text=True)


def test_upgrade_accepts_a_database_made_before_migrations(app_client):
    """Teammates' laptops have an old certificates.db; upgrading it must not fail."""
    db.run("DROP TABLE alembic_version")
    db.upgrade_to_latest()
    assert q("SELECT version_num FROM alembic_version") == [("0001",)]
