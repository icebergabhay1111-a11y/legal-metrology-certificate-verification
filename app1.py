from flask import Flask, render_template, request
import sqlite3
import os
import socket
import qrcode

# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

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

    conn.commit()

    conn.close()


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():

    return render_template("form.html")


# ============================================================
# CREATE CERTIFICATE
# ============================================================

@app.route("/submit", methods=["POST"])
def submit():

    # --------------------------------------------------------
    # GET FORM DATA
    # --------------------------------------------------------

    serial_number = request.form.get(
        "serial_number",
        ""
    ).strip()

    owner_name = request.form.get(
        "owner_name",
        ""
    ).strip()

    instrument_type = request.form.get(
        "instrument_type",
        ""
    ).strip()

    verification_date = request.form.get(
        "verification_date",
        ""
    ).strip()

    expiry_date = request.form.get(
        "expiry_date",
        ""
    ).strip()


    # --------------------------------------------------------
    # BASIC VALIDATION
    # --------------------------------------------------------

    if not serial_number:
        return "Serial number is required", 400

    if not owner_name:
        return "Owner name is required", 400

    if not instrument_type:
        return "Instrument type is required", 400

    if not verification_date:
        return "Verification date is required", 400

    if not expiry_date:
        return "Expiry date is required", 400


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
            expiry_date
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        serial_number,
        owner_name,
        instrument_type,
        verification_date,
        expiry_date
    ))

    certificate_id = cursor.lastrowid

    conn.commit()

    conn.close()


    # --------------------------------------------------------
    # CERTIFICATE CODE
    # --------------------------------------------------------

    certificate_code = f"CERT-{certificate_id:04d}"


    # --------------------------------------------------------
    # QR VERIFICATION URL
    # --------------------------------------------------------

    verification_url = (
        f"{BASE_URL}/verify/{certificate_code}"
    )


    # --------------------------------------------------------
    # CREATE QR FOLDER
    # --------------------------------------------------------

    qr_folder = os.path.join(
        "static",
        "qr"
    )

    os.makedirs(
        qr_folder,
        exist_ok=True
    )


    # --------------------------------------------------------
    # QR FILE NAME
    # --------------------------------------------------------

    qr_filename = (
        f"{certificate_code}.png"
    )

    qr_path = os.path.join(
        qr_folder,
        qr_filename
    )


    # --------------------------------------------------------
    # CREATE QR CODE
    # --------------------------------------------------------

    qr = qrcode.make(
        verification_url
    )

    qr.save(
        qr_path
    )


    # --------------------------------------------------------
    # URL USED BY HTML
    # --------------------------------------------------------

    qr_url = (
        f"/static/qr/{qr_filename}"
    )


    # --------------------------------------------------------
    # SHOW CERTIFICATE
    # --------------------------------------------------------

    return render_template(
        "certificate.html",

        certificate_id=certificate_code,

        serial_number=serial_number,

        owner_name=owner_name,

        instrument_type=instrument_type,

        verification_date=verification_date,

        expiry_date=expiry_date,

        qr_code=qr_url
    )


# ============================================================
# VERIFY CERTIFICATE
# ============================================================

@app.route("/verify/<certificate_id>")
def verify(certificate_id):

    # --------------------------------------------------------
    # REMOVE CERT PREFIX
    # --------------------------------------------------------

    if certificate_id.startswith("CERT-"):

        certificate_id = certificate_id.replace(
            "CERT-",
            ""
        )


    # --------------------------------------------------------
    # CONVERT ID TO INTEGER
    # --------------------------------------------------------

    try:

        certificate_id = int(
            certificate_id
        )

    except ValueError:

        return render_template(
            "verify.html",
            certificate=None
        )


    # --------------------------------------------------------
    # SEARCH DATABASE
    # --------------------------------------------------------

    conn = sqlite3.connect(
        DATABASE
    )

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            serial_number,
            owner_name,
            instrument_type,
            verification_date,
            expiry_date

        FROM certificates

        WHERE id = ?
    """, (
        certificate_id,
    ))

    certificate = cursor.fetchone()

    conn.close()


    # --------------------------------------------------------
    # SHOW VERIFICATION PAGE
    # --------------------------------------------------------

    return render_template(
        "verify.html",
        certificate=certificate
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

    print("Initializing database...")

    init_db()

    print("Database ready.")
    print()

    print("Starting server...")
    print()

    print(f"Laptop IP : {LAPTOP_IP}")
    print(f"Port      : {PORT}")
    print()

    print("Local URL:")
    print(
        f"http://127.0.0.1:{PORT}"
    )

    print()

    print("Network URL:")
    print(
        f"http://{LAPTOP_IP}:{PORT}"
    )

    print()

    print("QR Base URL:")
    print(
        BASE_URL
    )

    print()

    print("========================================")
    print("SERVER RUNNING")
    print("========================================")
    print()


    # --------------------------------------------------------
    # START FLASK
    # --------------------------------------------------------

    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False,
        use_reloader=False
    )