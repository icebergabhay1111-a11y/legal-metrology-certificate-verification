from flask import Flask, render_template, request
import sqlite3
import qrcode
import os

app = Flask(__name__)

# ============================================================
# SETTINGS
# ============================================================

LAPTOP_IP = "10.120.109.216"
PORT = 5050

DATABASE = "certificates.db"


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
# SUBMIT CERTIFICATE
# ============================================================

@app.route("/submit", methods=["POST"])
def submit():

    serial_number = request.form.get(
        "serial_number", ""
    ).strip()

    owner_name = request.form.get(
        "owner_name", ""
    ).strip()

    instrument_type = request.form.get(
        "instrument_type", ""
    ).strip()

    verification_date = request.form.get(
        "verification_date", ""
    ).strip()

    expiry_date = request.form.get(
        "expiry_date", ""
    ).strip()

    # --------------------------------------------------------
    # SAVE TO DATABASE
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
    # CERTIFICATE ID
    # --------------------------------------------------------

    certificate_code = f"CERT-{certificate_id:04d}"

    # --------------------------------------------------------
    # VERIFICATION URL
    # --------------------------------------------------------

    verification_url = (
        f"http://{LAPTOP_IP}:{PORT}"
        f"/verify/{certificate_code}"
    )

    print()
    print("NEW CERTIFICATE CREATED")
    print("-----------------------")
    print("Certificate ID :", certificate_code)
    print("Verification URL:")
    print(verification_url)
    print()

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
    # CREATE QR CODE
    # --------------------------------------------------------

    qr_filename = (
        f"{certificate_code}.png"
    )

    qr_path = os.path.join(
        qr_folder,
        qr_filename
    )

    qr = qrcode.make(
        verification_url
    )

    qr.save(qr_path)

    # URL used by certificate.html

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
    # REMOVE CERT- PREFIX
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

    print("Laptop IP :", LAPTOP_IP)
    print("Port      :", PORT)
    print()

    print("Local URL:")
    print(f"http://127.0.0.1:{PORT}")
    print()

    print("Network URL:")
    print(f"http://{LAPTOP_IP}:{PORT}")
    print()

    print("========================================")
    print("SERVER RUNNING")
    print("========================================")
    print()

    # --------------------------------------------------------
    # WAITRESS SERVER
    # --------------------------------------------------------

    from waitress import serve

    serve(
        app,
        host="0.0.0.0",
        port=PORT
    )