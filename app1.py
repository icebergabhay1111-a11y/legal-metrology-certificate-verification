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

app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

import auth
app.register_blueprint(auth.auth_bp)
auth.init_auth_db()
from auth import role_required, current_user, log as audit_log

# ============================================================
# CONFIGURATION
# ============================================================

DATABASE = "certificates.db"

# Render provides PORT automatically.
# Locally it will use 5050.
PORT = int(os.environ.get("PORT", 5050))

# ------------------------------------------------------------
# PUBLIC URL
# ------------------------------------------------------------
# When deployed on Render, set this environment variable:
#
# BASE_URL=https://your-app-name.onrender.com
#
# If BASE_URL is not set, the app automatically uses the
# laptop's local IP for local-network testing.
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
# RE-VERIFICATION PERIODS
# ============================================================
# Source: rule 27(2), Legal Metrology (General) Rules, 2011.
#
# IMPORTANT, AND SAY THIS ALOUD IF ASKED:
# These periods are corroborated by two law-firm publications.
# The gazette text of rule 27 has not been read by this team.
# They are therefore held as unverified and are configurable,
# not hard-coded law.
#
# The number of days before expiry at which a holder is
# reminded is also a configuration value, per State.
# ------------------------------------------------------------

REVERIFICATION_MONTHS = {
    "Weight":                          24,
    "Capacity measure":                24,
    "Length measure":                  24,
    "Measuring tape":                  24,
    "Beam scale":                      24,
    "Counter machine":                 24,
    "Storage tank":                    60,
    "Electronic weighing instrument":  12,
    "Weighbridge":                     12,
    "Fuel dispensing unit":            12,
    "Automatic weighing instrument":   12,
    "Other instrument":                12,
}

# Days before expiry at which the holder is reminded.
REMINDER_WINDOW_DAYS = int(
    os.environ.get("REMINDER_WINDOW_DAYS", 60)
)

PERIOD_SOURCE_NOTE = (
    "Re-verification periods follow rule 27(2), Legal Metrology "
    "(General) Rules, 2011. Held as unverified: corroborated by "
    "secondary publications, not yet read in the gazette. "
    "Configurable per State."
)


def add_months(start, months):
    """Return start shifted forward by whole months, clamping the day."""

    year = start.year + (start.month - 1 + months) // 12
    month = (start.month - 1 + months) % 12 + 1

    day = start.day

    while True:
        try:
            return date(year, month, day)
        except ValueError:
            day -= 1


def parse_date(text):
    """Return a date from YYYY-MM-DD, or None."""

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
    # Older databases were created before class of instrument,
    # maximum permissible error and the re-verification period
    # were recorded. Add the columns if they are missing.
    # --------------------------------------------------------

    cursor.execute("PRAGMA table_info(certificates)")

    existing = {row[1] for row in cursor.fetchall()}

    for column, ddl in [
        ("instrument_class",       "TEXT"),
        ("max_permissible_error",  "TEXT"),
        ("reverification_months",  "INTEGER"),
        ("officer_id",             "INTEGER"),
        ("officer_name",           "TEXT"),
    ]:
        if column not in existing:
            cursor.execute(
                f"ALTER TABLE certificates ADD COLUMN {column} {ddl}"
            )

    conn.commit()

    conn.close()


init_db()          # module level, so gunicorn app1:app works


def qr_data_uri(text):
    """Return a QR code for text as an inline data URI.

    Generated in memory rather than written to static/qr, because the
    deployment filesystem is not durable and an old QR image would
    disappear on redeploy.
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

    return render_template(
        "form.html",
        instrument_types=sorted(
            REVERIFICATION_MONTHS.items(),
            key=lambda item: (item[1], item[0])
        ),
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

    # Optional. Left blank in normal use: the system calculates
    # the expiry date itself. Filled in only to demonstrate an
    # already-expired certificate.
    expiry_override_text = request.form.get("expiry_date", "").strip()


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


    # --------------------------------------------------------
    # EXPIRY DATE
    # --------------------------------------------------------
    # The system knows the re-verification period for the
    # instrument type and calculates the expiry date itself.
    # The trader does not type it in.
    # --------------------------------------------------------

    months = REVERIFICATION_MONTHS[instrument_type]

    expiry_date = add_months(verification_date, months)

    if expiry_override_text:

        override = parse_date(expiry_override_text)

        if override is None:
            audit_log("certificate rejected", target=serial_number, detail="invalid expiry override")
            return "The expiry override is not a valid date", 400

        expiry_date = override


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
            officer_name
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        officer["full_name"]
    ))

    certificate_id = cursor.lastrowid

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

    certificate_code = f"CERT-{certificate_id:04d}"

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
            officer_name

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
    }

    return render_template(
        "verify.html",
        certificate=certificate,
        status=status,
        days=days,
        checked_on=today.isoformat(),
        reminder_window=REMINDER_WINDOW_DAYS,
        period_note=PERIOD_SOURCE_NOTE
    )


# ============================================================
# REMINDERS
# ============================================================
# The officer's view of what is about to lapse. This is the
# list the system would send reminders from.
# ------------------------------------------------------------

@app.route("/reminders")
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
