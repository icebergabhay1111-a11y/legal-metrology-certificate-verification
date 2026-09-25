"""
app1.py - the whole web app.

Team SahiDaam | SIH26036 | Online Verification System for Weighing and
Measuring Instruments.

WHAT EACH FILE DOES
    app1.py    this file - routes, DB tables, issuing a certificate
    auth.py    login, the 4 roles, audit log, dashboard, public reports
    config.py  reads states/*.json + enforcement.json
    signing.py Ed25519 signature so a fake cert can be spotted
    fraud.py   the 4 "catch a faker" rules (pure functions, no DB)
    states/    one JSON file per State. Add a file = add a State.

RUN IT LOCALLY
    pip install -r requirements.txt
    python app1.py           -> http://127.0.0.1:5050
    Login: lab1 / sahidaam2026   (see auth.py DEMO_USERS)

RUN THE TESTS
    python -m pytest -q      -> should say 43 passed

DEPLOY
    Start command: gunicorn app1:app
    Env vars to set: BASE_URL, SECRET_KEY, SIGNING_KEY
    See DEPLOY.md for the hosting comparison + why the DB keeps
    getting wiped on Render free.
"""

from flask import Flask, render_template, request
from datetime import date, datetime, timedelta
import sqlite3
import os
import io
import base64
import socket
import qrcode

# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

IS_PRODUCTION = os.environ.get("APP_ENV") == "production"

# The session cookie is signed with this. With the public default, anyone
# could forge a cookie that says role=admin. So production must set its own.
if IS_PRODUCTION and not os.environ.get("SECRET_KEY"):
    raise RuntimeError("SECRET_KEY is not set. Refusing to start in production.")
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

import auth
import config          # per-State settings + Shreyash's enforcement.json
import signing         # Ed25519 signature on every certificate
import fraud           # Krishna's four "catch a faker" rules

app.register_blueprint(auth.auth_bp)
auth.init_auth_db()
auth.ensure_demo_users()   # makes login work after every deploy - see auth.py
from auth import role_required, current_user, log as audit_log

# ============================================================
# CONFIGURATION
# ============================================================

DATABASE = "certificates.db"

# Render sets PORT for us. Locally we use 5050.
PORT = int(os.environ.get("PORT", 5050))

# ------------------------------------------------------------
# PUBLIC URL
# ------------------------------------------------------------
# On Render set this env var:
#     BASE_URL=https://your-app-name.onrender.com
# If it's not set we fall back to the laptop's local IP, which is fine
# for testing on the same wifi but useless for a QR a judge scans.
# i.e. ALWAYS set BASE_URL before a demo.
# ------------------------------------------------------------

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LAPTOP_IP = get_local_ip()

BASE_URL = os.environ.get(
    "BASE_URL",
    f"http://{LAPTOP_IP}:{PORT}"
).rstrip("/")


# ============================================================
# RE-VERIFICATION PERIODS + PER-STATE SETTINGS
# ============================================================
# These used to be hard-coded here. They now live in states/*.json
# and are read by config.py, bc Act s.53(2)(c) and (d) put the fee,
# the jurisdiction and the licence period in EACH State's hands.
# Adding a 4th State = drop a new file in states/. No code change.
#
# SAY THIS ALOUD IF ASKED: the 24 / 60 / 12 month periods come from
# rule 27(2) via two law-firm publications. We have NOT read the
# gazette. So they are config, not hard-coded law.
# ------------------------------------------------------------

PERIOD_SOURCE_NOTE = config.PERIOD_NOTE

# Kept only so old code + tests that still import it keep working.
REVERIFICATION_MONTHS = config.DEFAULT_MONTHS

# Default reminder window if a State file doesn't set one.
REMINDER_WINDOW_DAYS = int(os.environ.get("REMINDER_WINDOW_DAYS", 60))


def add_months(start, months):
    """Move a date forward N whole months.

    Clamps the day so 31 Jan + 1 month = 29 Feb, not a crash.
    """

    year = start.year + (start.month - 1 + months) // 12
    month = (start.month - 1 + months) % 12 + 1

    day = start.day

    while True:
        try:
            return date(year, month, day)
        except ValueError:
            day -= 1


def parse_date(text):
    """'2026-09-09' -> date. Junk -> None. Never raises."""

    try:
        return datetime.strptime(text.strip(), "%Y-%m-%d").date()
    except (ValueError, AttributeError):
        return None


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS certificates (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            serial_number TEXT NOT NULL,

            owner_name TEXT NOT NULL,

            instrument_type TEXT NOT NULL,

            verification_date TEXT NOT NULL,

            expiry_date TEXT NOT NULL

        )
    """)

    # --------------------------------------------------------
    # MIGRATION
    # --------------------------------------------------------
    # Old DBs were made before some of these columns existed.
    # Add whatever is missing. Safe to run every boot.
    # --------------------------------------------------------

    cursor.execute("PRAGMA table_info(certificates)")

    existing = {row[1] for row in cursor.fetchall()}

    for column, ddl in [
        ("instrument_class",       "TEXT"),
        ("max_permissible_error",  "TEXT"),
        ("reverification_months",  "INTEGER"),
        ("officer_id",             "INTEGER"),
        ("officer_name",           "TEXT"),
        ("signature",              "TEXT"),
        ("state_code",             "TEXT"),
    ]:
        if column not in existing:
            cursor.execute(
                f"ALTER TABLE certificates ADD COLUMN {column} {ddl}"
            )

    # Fraud alerts raised by fraud.py at the moment of issue.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fraud_alerts (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            at               TEXT NOT NULL,
            certificate_code TEXT,
            serial_number    TEXT,
            officer_name     TEXT,
            reason           TEXT NOT NULL,
            status           TEXT NOT NULL DEFAULT 'open'
        )
    """)

    conn.commit()

    conn.close()


init_db()          # module level, so gunicorn app1:app works


def qr_data_uri(text):
    """QR code as an inline data: URI (i.e. no file on disk).

    We build it in memory on purpose. Render's disk is wiped on every
    redeploy, so a saved PNG would 404 halfway through a demo.
    """

    image = qrcode.make(text)

    buffer = io.BytesIO()

    image.save(buffer, format="PNG")

    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")

    return f"data:image/png;base64,{encoded}"


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():

    user = current_user()
    state_code = (user or {}).get("state_code") or config.DEFAULT_STATE

    return render_template(
        "form.html",
        instrument_types=config.instrument_types(state_code),
        states=config.state_choices(),
        selected_state=state_code,
        today=date.today().isoformat(),
        period_note=PERIOD_SOURCE_NOTE
    )


# ============================================================
# CREATE CERTIFICATE
# ============================================================

@app.route("/submit", methods=["POST"])
@role_required("lab_officer", "district_officer", "admin")
def submit():

    officer = current_user()

    # --------------------------------------------------------
    # GET FORM DATA
    # --------------------------------------------------------

    serial_number = request.form.get("serial_number", "").strip()

    owner_name = request.form.get("owner_name", "").strip()

    instrument_type = request.form.get("instrument_type", "").strip()

    instrument_class = request.form.get("instrument_class", "").strip()

    max_permissible_error = request.form.get(
        "max_permissible_error", ""
    ).strip()

    verification_date_text = request.form.get(
        "verification_date", ""
    ).strip()

    # Which State's rulebook applies. Comes from the form, falling
    # back to the officer's own State.
    state_code = (request.form.get("state_code", "").strip().upper()
                  or officer.get("state_code") or config.DEFAULT_STATE)


    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    if not serial_number:
        audit_log("certificate rejected", detail="missing serial number")
        return "Serial number is required", 400

    if not owner_name:
        audit_log("certificate rejected", target=serial_number, detail="missing owner name")
        return "Owner name is required", 400

    if instrument_type not in REVERIFICATION_MONTHS:
        audit_log("certificate rejected", target=serial_number, detail="unknown instrument type")
        return "A known instrument type is required", 400

    verification_date = parse_date(verification_date_text)

    if verification_date is None:
        audit_log("certificate rejected", target=serial_number, detail="invalid verification date")
        return "A valid verification date is required", 400

    # Can't verify an instrument tomorrow. Blocks back-dating tricks
    # and plain typos.
    if verification_date > date.today():
        audit_log("certificate rejected", target=serial_number,
                  detail="verification date in the future")
        return "The verification date cannot be in the future", 400


    # --------------------------------------------------------
    # EXPIRY DATE
    # --------------------------------------------------------
    # The system works out the expiry itself from the instrument
    # type + the State's config. Nobody types a date in, so a cert
    # can never disagree with its own period.
    # --------------------------------------------------------

    # No expiry field on the form at all. Can't be typed in, so a
    # certificate can never contradict its own period.
    months = config.months_for(state_code, instrument_type)

    expiry_date = add_months(verification_date, months)


    # --------------------------------------------------------
    # INSERT INTO DATABASE
    # --------------------------------------------------------

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO certificates
        (
            serial_number,
            owner_name,
            instrument_type,
            verification_date,
            expiry_date,
            instrument_class,
            max_permissible_error,
            reverification_months,
            officer_id,
            officer_name,
            state_code
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        serial_number,
        owner_name,
        instrument_type,
        verification_date.isoformat(),
        expiry_date.isoformat(),
        instrument_class,
        max_permissible_error,
        months,
        officer["id"],
        officer["full_name"],
        state_code
    ))

    certificate_id = cursor.lastrowid
    certificate_code = f"CERT-{certificate_id:04d}"

    # ---- SIGN IT --------------------------------------------------
    # We sign the fields as they were just stored. Edit any of them
    # later and the /verify page will say "signature invalid".
    signature = signing.sign({
        "code": certificate_code,
        "serial_number": serial_number,
        "owner_name": owner_name,
        "instrument_type": instrument_type,
        "verified_on": verification_date.isoformat(),
        "expires_on": expiry_date.isoformat(),
        "officer_id": officer["id"],
    })
    cursor.execute("UPDATE certificates SET signature = ? WHERE id = ?",
                   (signature, certificate_id))

    # ---- FRAUD CHECKS ---------------------------------------------
    # Krishna's rules. We do NOT block the issue - we flag it, bc a
    # rule firing is a suspicion, not a conviction. The officer decides.
    existing = [
        {"code": f"CERT-{r[0]:04d}", "serial_number": r[1], "owner_name": r[2],
         "expires_on": r[3], "verified_on": r[4]}
        for r in cursor.execute(
            "SELECT id, serial_number, owner_name, expiry_date, "
            "verification_date FROM certificates WHERE id != ?",
            (certificate_id,)).fetchall()
    ]
    todays = cursor.execute(
        "SELECT id FROM certificates WHERE officer_id = ? AND "
        "verification_date = ?",
        (officer["id"], verification_date.isoformat())).fetchall()

    alerts = fraud.run_all_checks(
        new_cert={
            "code": certificate_code, "serial_number": serial_number,
            "owner_name": owner_name, "instrument_type": instrument_type,
            "verified_on": verification_date.isoformat(),
            "expires_on": expiry_date.isoformat(),
            "jurisdiction": officer.get("jurisdiction"),
            "state_code": state_code,
        },
        existing_certs=existing,
        officer={"id": officer["id"], "full_name": officer["full_name"],
                 "jurisdiction": officer.get("jurisdiction"),
                 "state_code": officer.get("state_code"), "kind": "lmo"},
        certs_today=todays,
        limit=config.daily_limit(state_code),
    )
    for a in alerts:
        cursor.execute(
            """INSERT INTO fraud_alerts (at, certificate_code, serial_number,
                   officer_name, reason) VALUES (?, ?, ?, ?, ?)""",
            (datetime.now().strftime("%Y-%m-%d %H:%M"), certificate_code,
             serial_number, officer["full_name"], a))

    conn.commit()

    conn.close()

    audit_log(
        "certificate issued",
        target=f"CERT-{certificate_id:04d}",
        detail=f"serial {serial_number}, owner {owner_name}",
    )


    # --------------------------------------------------------
    # CERTIFICATE CODE AND QR
    # --------------------------------------------------------

    verification_url = f"{BASE_URL}/verify/{certificate_code}"


    # --------------------------------------------------------
    # SHOW CERTIFICATE
    # --------------------------------------------------------

    return render_template(
        "certificate.html",

        certificate_id=certificate_code,

        serial_number=serial_number,

        owner_name=owner_name,

        instrument_type=instrument_type,

        instrument_class=instrument_class,

        max_permissible_error=max_permissible_error,

        verification_date=verification_date.isoformat(),

        expiry_date=expiry_date.isoformat(),

        reverification_months=months,

        officer_name=officer["full_name"],

        period_note=PERIOD_SOURCE_NOTE,

        verification_url=verification_url,

        qr_code=qr_data_uri(verification_url)
    )


# ============================================================
# VERIFY CERTIFICATE
# ============================================================
# A scan does not return the contents of a certificate.
# It returns the certificate's status on the day of scanning.
# ------------------------------------------------------------

@app.route("/verify/<certificate_id>")
def verify(certificate_id):

    today = date.today()

    # --------------------------------------------------------
    # REMOVE CERT PREFIX
    # --------------------------------------------------------

    if certificate_id.upper().startswith("CERT-"):

        certificate_id = certificate_id[5:]


    # --------------------------------------------------------
    # CONVERT ID TO INTEGER
    # --------------------------------------------------------

    try:
        certificate_id = int(certificate_id)

    except ValueError:

        return render_template(
            "verify.html",
            certificate=None,
            status="NOT FOUND",
            checked_on=today.isoformat()
        )


    # --------------------------------------------------------
    # SEARCH DATABASE
    # --------------------------------------------------------

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            serial_number,
            owner_name,
            instrument_type,
            verification_date,
            expiry_date,
            instrument_class,
            max_permissible_error,
            reverification_months,
            officer_name,
            signature,
            state_code,
            officer_id

        FROM certificates

        WHERE id = ?
    """, (certificate_id,))

    row = cursor.fetchone()

    conn.close()

    if row is None:

        return render_template(
            "verify.html",
            certificate=None,
            status="NOT FOUND",
            checked_on=today.isoformat()
        )


    # --------------------------------------------------------
    # STATUS ON THE DAY OF SCANNING
    # --------------------------------------------------------

    expiry_date = parse_date(row[5])

    if expiry_date is None:

        status = "UNREADABLE EXPIRY DATE"
        days = None

    elif expiry_date < today:

        status = "EXPIRED"
        days = (today - expiry_date).days

    elif (expiry_date - today).days <= REMINDER_WINDOW_DAYS:

        status = "EXPIRING SOON"
        days = (expiry_date - today).days

    else:

        status = "VALID"
        days = (expiry_date - today).days


    certificate = {
        "code":            f"CERT-{row[0]:04d}",
        "serial_number":   row[1],
        "owner_name":      row[2],
        "instrument_type": row[3],
        "verified_on":     row[4],
        "expires_on":      row[5],
        "instrument_class": row[6] or "Not recorded",
        "max_permissible_error": row[7] or "Not recorded",
        "reverification_months": row[8],
        "officer_name": row[9] or "Not recorded",
        "state_code": row[11] or "",
    }

    # ---- IS THE SIGNATURE STILL GOOD? -----------------------------
    # We rebuild the payload from what is stored RIGHT NOW. If anyone
    # edited a field in the DB, this comes back False.
    signature_ok = signing.verify({
        "code": certificate["code"],
        "serial_number": row[1],
        "owner_name": row[2],
        "instrument_type": row[3],
        "verified_on": row[4],
        "expires_on": row[5],
        "officer_id": row[12],
    }, row[10])

    # ---- WHAT THE LAW SAYS, IF IT HAS EXPIRED ---------------------
    enforcement = (config.enforcement_for("expired certificate")
                   if status == "EXPIRED" else None)

    return render_template(
        "verify.html",
        certificate=certificate,
        status=status,
        days=days,
        checked_on=today.isoformat(),
        reminder_window=config.reminder_days(certificate.get("state_code")),
        period_note=PERIOD_SOURCE_NOTE,
        signature_ok=signature_ok,
        enforcement=enforcement
    )


# ============================================================
# REMINDERS
# ============================================================
# Officer's view of what's about to lapse. Login required - this
# used to be wide open, which meant anyone could read the whole
# due-list w/o an account.
# ------------------------------------------------------------

@app.route("/reminders")
@role_required("lab_officer", "district_officer", "admin")
def reminders():

    today = date.today()

    cutoff = today + timedelta(days=REMINDER_WINDOW_DAYS)

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            serial_number,
            owner_name,
            instrument_type,
            expiry_date

        FROM certificates

        ORDER BY expiry_date ASC
    """)

    rows = cursor.fetchall()

    conn.close()

    due = []
    expired = []

    for row in rows:

        expiry_date = parse_date(row[4])

        if expiry_date is None:
            continue

        item = {
            "code":            f"CERT-{row[0]:04d}",
            "serial_number":   row[1],
            "owner_name":      row[2],
            "instrument_type": row[3],
            "expires_on":      row[4],
            "days":            (expiry_date - today).days,
        }

        if expiry_date < today:
            expired.append(item)

        elif expiry_date <= cutoff:
            due.append(item)

    return render_template(
        "reminders.html",
        due=due,
        expired=expired,
        today=today.isoformat(),
        reminder_window=REMINDER_WINDOW_DAYS
    )


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print()
    print("========================================")
    print("       LEGAL METROLOGY SYSTEM")
    print("========================================")
    print()

    print(f"Laptop IP : {LAPTOP_IP}")
    print(f"Port      : {PORT}")
    print(f"QR base   : {BASE_URL}")
    print()

    print("========================================")
    print("SERVER RUNNING")
    print("========================================")
    print()

    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False,
        use_reloader=False
    )
