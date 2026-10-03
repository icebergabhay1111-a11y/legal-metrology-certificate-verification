"""
app1.py - the web app: settings, public pages and officer pages.

Team VITV SahiDaam | SIH26036 | Online Verification System for Weighing
and Measuring Instruments. Student prototype.

WHAT EACH FILE DOES
    app1.py     this file - start-up and every page except login/dashboard
    auth.py     login, the four roles, audit log, dashboard, public reports
    certs.py    certificate codes, status rules, lookups
    signing.py  Ed25519 signatures with key ids
    fraud.py    the four "catch a faker" rules (pure functions)
    errors.py   every error code (LM-/SYS-) and the error page
    security.py CSRF, security headers, rate limits, request ids
    config.py   per-State settings (states/*.json) and enforcement.json
    db.py       SQLite locally, PostgreSQL when DATABASE_URL is set
    clock.py    India's date and time
    seed_demo.py  realistic, obviously fake test data

RUN IT:   pip install -r requirements.txt  then  python app1.py
TEST IT:  python -m pytest -q
DEPLOY:   gunicorn app1:app   - settings in DEPLOY.md
"""

import base64
import io
import logging
import os
import re
import socket
from datetime import date
from urllib.parse import quote

import qrcode
from flask import (Flask, Response, abort, g, jsonify, redirect, render_template,
                   request, send_from_directory, url_for)

import clock

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__)
IS_PRODUCTION = os.environ.get("APP_ENV") == "production"

# The session cookie is signed with this. With the public default, anyone
# could forge a cookie that says role=admin, so production must set its own.
if IS_PRODUCTION and not os.environ.get("SECRET_KEY"):
    raise RuntimeError("SECRET_KEY is not set. Refusing to start in production.")
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

import auth          # noqa: E402  (these need the app above to exist)
import certs         # noqa: E402
import config        # noqa: E402
import db            # noqa: E402
import errors        # noqa: E402
import fraud         # noqa: E402
import security      # noqa: E402
import signing       # noqa: E402

security.init_app(app, production=IS_PRODUCTION)
errors.init_app(app)
app.register_blueprint(auth.auth_bp)
db.upgrade_to_latest()      # create or update every table - see migrations/
auth.ensure_demo_users()    # demo logins exist after every deploy - see auth.py

from auth import current_user, log as audit_log, role_required  # noqa: E402

OFFICERS = ("lab_officer", "district_officer", "admin")
REVOKERS = ("district_officer", "admin")
PORT = int(os.environ.get("PORT", 5050))
PERIOD_SOURCE_NOTE = config.PERIOD_NOTE

# Limits on what a form may contain. '|' separates fields in the signed
# text and the QR code, so it may not appear inside a field.
FIELD_LIMITS = {"serial_number": 40, "owner_name": 120, "instrument_class": 40,
                "max_permissible_error": 40, "jurisdiction": 60}
BAD_CHARS = re.compile(r"[|\x00-\x1f\x7f]")


def local_ip():
    """This laptop's address on the wifi, for QR codes during local testing."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


# The QR code points here. ALWAYS set BASE_URL on the server.
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/") or f"http://{local_ip()}:{PORT}"


def add_months(start, months):
    """Move a date forward whole months; 31 Jan + 1 month = 28/29 Feb."""
    year = start.year + (start.month - 1 + months) // 12
    month = (start.month - 1 + months) % 12 + 1
    day = start.day
    while True:
        try:
            return date(year, month, day)
        except ValueError:
            day -= 1


def qr_data_uri(text):
    """QR code as an inline data: URI, so no image file is ever written."""
    image = qrcode.make(text, error_correction=qrcode.constants.ERROR_CORRECT_M)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


def qr_text(row):
    """What the QR holds: the status page URL, plus the signed fields after '#'.

    A phone camera opens the URL (the part after '#' never reaches the
    server). The offline checker reads the part after '#' and verifies the
    signature with no network. Format: v1|code|serial|owner|type|verified|
    expires|officer id|key id|signature.
    """
    fields = certs.signed_fields(row)
    parts = ["v1"]
    for name in signing.FIELD_ORDER:
        parts.append(str(fields[name]))
    parts.append(row.key_id or signing.KEY_ID)
    parts.append(row.signature or "")
    # Percent-encode each part (spaces, '&', Hindi letters) so the URL stays valid.
    encoded = [quote(part, safe="-.:") for part in parts]
    return f"{BASE_URL}/verify/{row.code}#" + "|".join(encoded)


@app.template_filter("nice")
def nice_date(value):
    """'2026-08-28' -> '28 Aug 2026' for people; stored dates stay ISO."""
    parsed = certs.parse_date(value)
    return parsed.strftime("%d %b %Y") if parsed else value


@app.context_processor
def page_globals():
    """Every template gets the logged-in user (or None) as `me`."""
    return {"me": current_user(), "national_contacts": config.NATIONAL_CONTACTS}


# ============================================================
# PUBLIC PAGES
# ============================================================

@app.route("/")
def home():
    """Public home: the certificate search."""
    return render_template("home.html")


@app.route("/verify")
def verify_search():
    """Search box: a certificate code goes to its page; anything else is a serial."""
    security.rate_limit("lookup")
    text = request.args.get("code", "").strip()[:60]
    if not text:
        return render_template("home.html", error="Enter a certificate ID or a serial number."), 400
    code = certs.normalise_code(text)
    if code and certs.find(code):
        return redirect(url_for("verify", code=code))
    results = certs.by_serial(text)
    if len(results) == 1:
        return redirect(url_for("verify", code=results[0][0].code))
    return render_template("search.html", query=text, results=results)


@app.route("/verify/<code>")
def verify(code):
    """A certificate's status on the day it is checked, not a stored status."""
    security.rate_limit("lookup")
    today = clock.today()
    normal = certs.normalise_code(code)
    if normal and normal != code:
        return redirect(url_for("verify", code=normal), 301)
    row = certs.find(normal)
    if row is None:
        g.no_store = True
        return render_template("verify.html", certificate=None, status="NOT FOUND",
                               result_code="LM-101", checked_on=today.isoformat(),
                               contacts=config.contacts_for(None)), 404
    g.no_store = True       # a status is today's; no shared cache may keep it
    result = certs.assess(row, today)
    enforcement = config.enforcement_for("expired certificate") if result["status"] == "EXPIRED" else None
    return render_template(
        "verify.html", certificate=row, status=result["status"], result_code=result["code"],
        days=result["days"], signature_ok=result["signature_ok"], checked_on=today.isoformat(),
        reminder_window=config.reminder_days(row.state_code), period_note=PERIOD_SOURCE_NOTE,
        enforcement=enforcement, timeline=validity_timeline(row, today, result["status"]),
        contacts=config.contacts_for(row.state_code), can_revoke=_can_revoke(row),
    )


def validity_timeline(row, today, status):
    """How much of the validity period has passed, for the progress bar."""
    start, end = certs.parse_date(row.verification_date), certs.parse_date(row.expiry_date)
    if status not in ("VALID", "EXPIRING SOON", "EXPIRED") or not start or not end or end <= start:
        return None
    pct = max(0, min(100, round(100 * (today - start).days / (end - start).days)))
    return {"pct": pct, "tone": {"EXPIRED": "bad", "EXPIRING SOON": "warn"}.get(status, "")}


def _can_revoke(row):
    """Show the revoke form only to district officers and admins, on live records."""
    user = current_user()
    return bool(user and user["role"] in REVOKERS and not row.revoked_at)


INFO_PAGES = ("help", "accessibility", "privacy", "terms")


@app.route("/info/<page>")
def info(page):
    """Help, accessibility statement, privacy and terms pages."""
    if page not in INFO_PAGES:
        abort(404)
    states = config.state_contacts()
    any_state = any(entries for _, entries in states)
    return render_template(f"info_{page}.html", active=page, national=config.NATIONAL_CONTACTS,
                           states=states, any_state=any_state)


@app.route("/healthz")
def healthz():
    """Liveness for the uptime monitor. Never touches the database, so a
    ping every 5 minutes does not keep the free database awake."""
    return Response("ok", mimetype="text/plain")


# ---- offline checker -------------------------------------------------

@app.route("/offline")
def offline():
    """Checker that verifies a QR's signature on the phone, without a network."""
    return render_template("offline.html", active="offline")


@app.route("/keys.json")
def keys_json():
    """Public keys that can verify certificates. Safe to publish."""
    return jsonify(keys=signing.public_keys())


@app.route("/sw.js")
def service_worker():
    """Served from the site root so it may cache the whole site's checker."""
    response = send_from_directory(os.path.join(app.root_path, "static", "js"), "sw.js",
                                   mimetype="application/javascript", max_age=0)
    response.headers["Service-Worker-Allowed"] = "/"
    return response


@app.route("/favicon.ico")
def favicon():
    """Browsers ask for this on every site; answer instead of logging a 404."""
    return send_from_directory(os.path.join(app.root_path, "static"), "icon-192.png",
                               mimetype="image/png", max_age=86400)


@app.route("/manifest.webmanifest")
def manifest():
    """Lets a phone install the offline checker like an app."""
    return send_from_directory(os.path.join(app.root_path, "static"), "manifest.webmanifest",
                               mimetype="application/manifest+json")


# ============================================================
# OFFICER PAGES
# ============================================================

@app.route("/issue")
@role_required(*OFFICERS)
def issue():
    """Officer form for issuing a certificate."""
    user = current_user()
    picked = request.args.get("state_code", "").upper()
    state_code = picked if picked in config.STATES else (user.get("state_code") or config.DEFAULT_STATE)
    return _issue_form(state_code, {}, {})


def _issue_form(state_code, values, problems, status=200):
    """Render the issue form, keeping what was typed and showing each problem by its field."""
    return render_template(
        "form.html", instrument_types=config.instrument_types(state_code),
        states=config.state_choices(), jurisdictions=config.jurisdictions(state_code),
        selected_state=state_code, today=clock.today().isoformat(), values=values,
        problems=problems, period_note=PERIOD_SOURCE_NOTE,
    ), status


def read_issue_form(form, officer):
    """Clean and check the issue form. Returns (values, {field: (code, message)})."""
    values = {name: " ".join(form.get(name, "").split()) for name in
              ("serial_number", "owner_name", "instrument_type", "instrument_class",
               "max_permissible_error", "verification_date", "state_code", "jurisdiction")}
    values["serial_number"] = certs.normalise_serial(values["serial_number"])
    values["state_code"] = values["state_code"].upper() or officer.get("state_code") or config.DEFAULT_STATE
    problems = {}
    for name, limit in FIELD_LIMITS.items():
        if len(values[name]) > limit:
            problems[name] = ("LM-306", f"Use at most {limit} characters.")
        elif BAD_CHARS.search(values[name]):
            problems[name] = ("LM-306", "The character | and control characters are not allowed.")
    if not values["serial_number"]:
        problems["serial_number"] = ("LM-306", "Serial number is required.")
    if not values["owner_name"]:
        problems["owner_name"] = ("LM-306", "Owner name is required.")
    if values["state_code"] not in config.STATES:
        problems["state_code"] = ("LM-303", errors.message("LM-303"))
    elif not values["instrument_type"]:
        problems["instrument_type"] = ("LM-306", "Choose an instrument type.")
    elif values["instrument_type"] not in dict(config.instrument_types(values["state_code"])):
        problems["instrument_type"] = ("LM-302", errors.message("LM-302"))
    places = config.jurisdictions(values["state_code"])
    if places and values["jurisdiction"] not in places:
        problems["jurisdiction"] = ("LM-306", "Choose the district where the instrument is.")
    verified = certs.parse_date(values["verification_date"])
    if verified is None:
        problems["verification_date"] = ("LM-306", "Enter the date the instrument was verified.")
    elif verified > clock.today():
        problems["verification_date"] = ("LM-301", errors.message("LM-301"))
    elif (clock.today() - verified).days > 3660:
        problems["verification_date"] = ("LM-306", "A verification more than ten years old cannot be recorded.")
    return values, problems


@app.route("/submit", methods=["POST"])
@role_required(*OFFICERS)
def submit():
    """Issue, sign and fraud-check a certificate in one database transaction."""
    security.rate_limit("issue")
    officer = current_user()
    values, problems = read_issue_form(request.form, officer)
    if problems:
        first = next(iter(problems.values()))
        audit_log("certificate rejected", target=values["serial_number"],
                  detail=f"{first[0]}: {first[1]}")
        return _issue_form(values["state_code"], values, problems, 400)

    code = create_certificate(values, officer)
    audit_log("certificate issued", target=code,
              detail=f"serial {values['serial_number']}, owner {values['owner_name']}")
    # Post/Redirect/Get: refreshing the next page cannot issue a duplicate.
    return redirect(url_for("certificate", code=code, issued=1))


def create_certificate(values, officer, code=None):
    """Sign, store and fraud-check one certificate in a single transaction.

    values: the cleaned form (see read_issue_form). officer: current_user().
    code: only the demo seeder passes one; normally a random code is made.
    Returns the certificate's public code.
    """
    verified = certs.parse_date(values["verification_date"])
    months = config.months_for(values["state_code"], values["instrument_type"])
    expires = add_months(verified, months)
    code = code or _unused_code()
    signature, key_id = signing.sign({
        "code": code, "serial_number": values["serial_number"], "owner_name": values["owner_name"],
        "instrument_type": values["instrument_type"], "verified_on": verified.isoformat(),
        "expires_on": expires.isoformat(), "officer_id": officer["id"],
    })
    with db.engine.begin() as conn:
        conn.execute(db.text("""
            INSERT INTO certificates
                (code, serial_number, owner_name, instrument_type, verification_date,
                 expiry_date, instrument_class, max_permissible_error, reverification_months,
                 officer_id, officer_name, state_code, jurisdiction, signature, key_id)
            VALUES (:code, :serial, :owner, :itype, :verified, :expires, :iclass, :mpe,
                    :months, :officer_id, :officer_name, :state, :place, :sig, :kid)
        """), dict(code=code, serial=values["serial_number"], owner=values["owner_name"],
                   itype=values["instrument_type"], verified=verified.isoformat(),
                   expires=expires.isoformat(), iclass=values["instrument_class"],
                   mpe=values["max_permissible_error"], months=months, officer_id=officer["id"],
                   officer_name=officer["full_name"], state=values["state_code"],
                   place=values["jurisdiction"], sig=signature, kid=key_id))
        for alert_code, reason in _fraud_checks(conn, code, values, verified, expires, officer):
            conn.execute(db.text(
                "INSERT INTO fraud_alerts (at, code, certificate_code, serial_number, officer_name, reason) "
                "VALUES (:at, :ac, :code, :serial, :officer, :reason)"),
                dict(at=clock.stamp(), ac=alert_code, code=code, serial=values["serial_number"],
                     officer=officer["full_name"], reason=reason))
    return code


def _unused_code():
    """A random code not already in use (a clash is about 1 in 10^11)."""
    while True:
        code = certs.new_code()
        if certs.find(code) is None:
            return code


def _fraud_checks(conn, code, values, verified, expires, officer):
    """Run Krishna's four rules on the new certificate. Returns [(LM code, message)].

    A rule firing is a suspicion, not a finding: the certificate is still
    issued and the officer sees the alert on the dashboard.
    """
    same_serial = conn.execute(db.text(
        "SELECT code, serial_number, owner_name, expiry_date, verification_date FROM certificates "
        "WHERE UPPER(serial_number) = :s AND code != :c"),
        dict(s=values["serial_number"], c=code)).fetchall()
    existing = [{"code": r.code, "serial_number": r.serial_number, "owner_name": r.owner_name,
                 "expires_on": r.expiry_date, "verified_on": r.verification_date} for r in same_serial]
    todays = conn.execute(db.text(
        "SELECT id FROM certificates WHERE officer_id = :o AND verification_date = :d"),
        dict(o=officer["id"], d=verified.isoformat())).fetchall()
    return fraud.run_all_checks_coded(
        new_cert={"code": code, "serial_number": values["serial_number"],
                  "owner_name": values["owner_name"], "instrument_type": values["instrument_type"],
                  "verified_on": verified.isoformat(), "expires_on": expires.isoformat(),
                  "jurisdiction": values["jurisdiction"], "state_code": values["state_code"]},
        existing_certs=existing,
        officer={"id": officer["id"], "full_name": officer["full_name"],
                 "jurisdiction": officer.get("jurisdiction"), "state_code": officer.get("state_code"),
                 "kind": "lmo"},
        certs_today=todays, limit=config.daily_limit(values["state_code"]),
    )


@app.route("/certificate/<code>")
@role_required(*OFFICERS)
def certificate(code):
    """Printable certificate with its QR code. Can be reprinted any time."""
    row = certs.find(certs.normalise_code(code))
    if row is None:
        abort(404)
    g.no_store = True
    text = qr_text(row)
    return render_template("certificate.html", c=row, qr_code=qr_data_uri(text),
                           verification_url=text.split("#")[0], period_note=PERIOD_SOURCE_NOTE,
                           just_issued=request.args.get("issued") == "1")


@app.route("/revoke/<code>", methods=["POST"])
@role_required(*REVOKERS)
def revoke(code):
    """Withdraw a certificate issued in error or for a seized instrument."""
    row = certs.find(certs.normalise_code(code))
    if row is None:
        abort(404)
    reason = " ".join(request.form.get("reason", "").split())[:300]
    if row.revoked_at:
        return redirect(url_for("verify", code=row.code))
    if len(reason) < 5:
        result = certs.assess(row)
        return render_template(
            "verify.html", certificate=row, status=result["status"], result_code=result["code"],
            days=result["days"], signature_ok=result["signature_ok"],
            checked_on=clock.today().isoformat(), reminder_window=config.reminder_days(row.state_code),
            period_note=PERIOD_SOURCE_NOTE, enforcement=None, timeline=None,
            contacts=config.contacts_for(row.state_code), can_revoke=True,
            revoke_error="Give the reason for revoking (at least 5 characters).",
        ), 400
    user = current_user()
    db.run("UPDATE certificates SET revoked_at = :at, revoked_by = :by, revoke_reason = :why "
           "WHERE code = :c AND revoked_at IS NULL",
           at=clock.stamp(), by=user["full_name"], why=reason, c=row.code)
    audit_log("certificate revoked", target=row.code, detail=reason)
    return redirect(url_for("verify", code=row.code))


@app.route("/reminders")
@role_required(*OFFICERS)
def reminders():
    """What has lapsed and what falls due inside each State's window."""
    due, expired = certs.due_and_expired()
    return render_template("reminders.html", due=due, expired=expired,
                           today=clock.today().isoformat(), windows=config.reminder_windows())


@app.route("/admin/health")
@role_required("admin")
def health():
    """SYS-level checks an administrator can read at a glance."""
    checks = {}
    try:
        checks["database"] = (True, db.engine.dialect.name)
        checks["migration"] = (True, db.fetch_one("SELECT version_num FROM alembic_version")[0])
        counts = db.fetch_one("SELECT COUNT(*) FROM certificates")[0]
        checks["certificates"] = (True, str(counts))
    except Exception as exc:     # SYS-501: report it here rather than crash the page
        checks["database"] = (False, f"SYS-501 {type(exc).__name__}")
    checks["signing key"] = (True, f"key id {signing.KEY_ID}; {len(signing.KEYRING)} key(s) can verify")
    checks["State settings"] = (not config.STATE_ERRORS,
                                f"{len(config.STATES)} loaded" + (f"; SYS-503 failed: {', '.join(config.STATE_ERRORS)}" if config.STATE_ERRORS else ""))
    stale = config.stale_contacts()
    checks["contacts"] = (not stale, f"{len(stale)} older than 180 days" if stale else "none stale")
    checks["base URL"] = (bool(os.environ.get("BASE_URL")) or not IS_PRODUCTION, BASE_URL)
    return render_template("health.html", checks=checks, active="health")


if __name__ == "__main__":
    print(f"Sahi Daam running on port {PORT}. QR codes point to {BASE_URL}")
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
