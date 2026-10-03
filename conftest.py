"""
conftest.py - shared test helpers. pytest loads this file by itself.

Every test starts from an empty database (SQLite file, or PostgreSQL when
DATABASE_URL is set, as in CI) and a freshly started app.
"""

import datetime
import importlib
import os
import re
import time

import pytest

import clock
import db
import security

DB = "certificates.db"
TODAY = clock.today()          # India's date, same as the app
PW = "sahidaam2026"            # the local-only demo password


def q(sql, **params):
    """Run a read-only query through db.py; rows come back as tuples."""
    return [tuple(row) for row in db.fetch_all(sql, **params)]


def drop_db():
    """Empty the database. Refuses outright if APP_ENV says production."""
    if os.environ.get("APP_ENV") == "production":
        raise RuntimeError("refusing to wipe a production database")
    if db.engine.dialect.name == "postgresql":
        db.run("DROP TABLE IF EXISTS certificates, fraud_alerts, users, audit, applications, "
               "reports, alembic_version CASCADE")
        return
    for _ in range(5):
        if not os.path.exists(DB):
            return
        try:
            os.remove(DB)
            return
        except PermissionError:      # Windows can hold the file a moment longer
            time.sleep(0.2)
    raise RuntimeError(f"could not delete {DB} - close anything that has it open.")


@pytest.fixture()
def app_client():
    """Fresh database + fresh app + a test client, for every test."""
    drop_db()
    security.reset_rate_limits()
    import app1
    importlib.reload(app1)
    app1.app.config["TESTING"] = True
    yield app1.app.test_client()
    drop_db()


def post(c, url, data=None):
    """POST the way the browser does: with this session's CSRF token."""
    with c.session_transaction() as s:
        token = s.setdefault("csrf_token", "test-token-0123456789")
    return c.post(url, data={**(data or {}), "csrf_token": token})


def login(c, user="lab1", password=PW):
    """Sign in as a demo user."""
    return post(c, "/login", {"username": user, "password": password})


def issue(c, serial="WB-4471", itype="Weighbridge", days_ago=0, state="TN",
          owner="Sharma Traders (sample)", place="Chennai"):
    """Submit the issue form. Returns the response."""
    return post(c, "/submit", {
        "serial_number": serial, "owner_name": owner, "instrument_type": itype,
        "instrument_class": "Class III", "max_permissible_error": "20 kg",
        "verification_date": (TODAY - datetime.timedelta(days=days_ago)).isoformat(),
        "state_code": state, "jurisdiction": place,
    })


def issued_code(response):
    """The new certificate's code, from the redirect after issuing."""
    match = re.search(r"/certificate/([A-Z0-9-]+)", response.headers.get("Location", ""))
    assert match, f"no certificate in redirect: {response.status_code}"
    return match.group(1)


def issue_code(c, **kwargs):
    """Issue a certificate and return its code."""
    return issued_code(issue(c, **kwargs))


def status_of(c, code):
    """(status shown on the page, page text)."""
    body = c.get(f"/verify/{code}", follow_redirects=True).get_data(as_text=True)
    m = re.search(r'data-status="([^"]+)"', body)
    return (m.group(1) if m else "NONE"), body
