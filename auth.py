"""
auth.py — login, roles, and the audit log.

Owner: Abhay (26BDE0132) — branch feat/auth-and-roles

app1.py wires this in with `app.register_blueprint(auth.auth_bp)`.
Its tables (users, audit, reports) are created by migrations/, not here.

One more thing is NOT optional but IS a small edit to app1.py's own
code, not to this file: stamping officer_id / officer_name onto a
certificate at the moment of issue. That patch is written out in
full, ready to paste, in INTEGRATION.md next to this file.
"""

import functools
import os
from datetime import date, datetime, timedelta

from flask import (
    Blueprint, Response, g, redirect, render_template,
    request, session, url_for,
)
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash

import db


# Four roles. Do not add a fifth — see the task brief.
ROLES = ("trader", "lab_officer", "district_officer", "admin")

auth_bp = Blueprint("auth", __name__)


# ============================================================
# DATABASE
# ============================================================

# Tables are created by migrations (migrations/versions/), not here.
# Queries go through db.py so the same SQL runs on SQLite and PostgreSQL.


# ============================================================
# DEMO ACCOUNTS - THIS IS WHAT MAKES LOGIN WORK ON RENDER
# ============================================================
# THE PROBLEM IT FIXES:
# Render's free tier has an EPHEMERAL filesystem. Their own docs say
# "any changes to your web service's filesystem (uploaded images, local
# SQLite databases, etc.) are lost every time the service redeploys,
# restarts, or spins down." So certificates.db - incl. the users table -
# is wiped on every deploy. seed_users.py can't help bc there's no shell
# on the free plan. Result: 0 users -> nobody can log in.
#
# THE FIX: create the accounts at startup, every startup. Idempotent,
# i.e. running it again does nothing if the user already exists.
#
# Passwords come from env vars if set (do that on Render), else the
# demo defaults below. Change them by setting the env vars - no code
# edit, no redeploy of the code itself.
# ------------------------------------------------------------

DEMO_USERS = [
    # username,   env var for pw,   full name,                 role,               state, jurisdiction
    ("trader1",   "PW_TRADER",      "Ramesh Trader",           "trader",           "TN", "Chennai"),
    ("lab1",      "PW_LAB",         "Priya Lab Officer",       "lab_officer",      "TN", "Chennai"),
    ("district1", "PW_DISTRICT",    "Suresh District Officer", "district_officer", "TN", "Chennai"),
    ("admin1",    "PW_ADMIN",       "Admin User",              "admin",            "TN", "State HQ"),
    ("mz1",       "PW_MZ",          "Lalrin Lab Officer",      "lab_officer",      "MZ", "Aizawl"),
]

DEFAULT_DEMO_PASSWORD = "sahidaam2026"


def ensure_demo_users():
    """Make sure the four demo logins exist. Runs on every boot.

    Skips anyone already there, so it never overwrites a real password.
    """
    for username, env_var, full_name, role, state_code, jurisdiction in DEMO_USERS:
        if db.fetch_one("SELECT id FROM users WHERE username = :u", u=username):
            continue
        password = os.environ.get(env_var)
        if not password and os.environ.get("APP_ENV") == "production":
            # Never fall back to the password printed in public source.
            print(f"WARNING: {env_var} not set - account '{username}' not created.")
            continue
        password = password or DEFAULT_DEMO_PASSWORD
        db.run(
            """INSERT INTO users
               (username, password_hash, full_name, role, state_code, jurisdiction)
               VALUES (:u, :h, :name, :role, :state, :jur)""",
            u=username, h=generate_password_hash(password), name=full_name,
            role=role, state=state_code, jur=jurisdiction,
        )


# ============================================================
# AUDIT LOG
# ============================================================
# One function. Every event goes through this — do not write
# the INSERT out again somewhere else.
# ------------------------------------------------------------

def log(action, target="", detail=""):
    actor_id = session.get("user_id")
    actor_name = session.get("full_name", "anonymous")

    db.run(
        """INSERT INTO audit (at, actor_id, actor_name, action, target, detail)
           VALUES (:at, :actor_id, :actor_name, :action, :target, :detail)""",
        at=datetime.now().strftime("%Y-%m-%d %H:%M"), actor_id=actor_id,
        actor_name=actor_name, action=action, target=target, detail=detail,
    )


# ============================================================
# SESSION HELPERS
# ============================================================

def current_user():
    """Dict for the logged-in user, or None."""
    if "user_id" not in session:
        return None
    return {
        "id": session["user_id"],
        "username": session["username"],
        "full_name": session["full_name"],
        "role": session["role"],
    }


def role_required(*allowed_roles):
    """Route decorator. Refuses server-side — not a hidden button.

    Not logged in -> sent to the login page.
    Logged in but wrong role -> HTTP 403, page says so.
    """
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()

            if user is None:
                # Only carry a "next" redirect for plain page visits (GET).
                # If someone was blocked while POSTing a form (e.g. /submit),
                # sending them back with a GET after login would hit the
                # same "Method Not Allowed" wall the form exists to avoid —
                # so send them to the homepage instead in that case.
                if request.method == "GET":
                    return redirect(url_for("auth.login", next=request.path))
                return redirect(url_for("auth.login"))

            if user["role"] not in allowed_roles:
                return render_template("403.html", role=user["role"]), 403

            g.user = user
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ============================================================
# LOGIN / LOGOUT
# ============================================================

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    found = db.fetch_one("SELECT * FROM users WHERE username = :u", u=username)
    row = found._mapping if found else None

    # Same message either way — never reveal whether the
    # username exists.
    generic_error = "Incorrect username or password."

    if row is None:
        log("failed login", target=username, detail="no such user")
        return render_template("login.html", error=generic_error), 401

    if not check_password_hash(row["password_hash"], password):
        log("failed login", target=username, detail="wrong password")
        return render_template("login.html", error=generic_error), 401

    session["user_id"] = row["id"]
    session["username"] = row["username"]
    session["full_name"] = row["full_name"]
    session["role"] = row["role"]

    log("login", target=username)

    return redirect(safe_next(request.args.get("next")))


def safe_next(target):
    """Only follow ?next= to a page on this site, never to another website."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("auth.dashboard")


@auth_bp.route("/logout")
def logout():
    username = session.get("username", "")
    log("logout", target=username)
    session.clear()
    return redirect(url_for("home"))


# ============================================================
# PUBLIC REPORT FORM — no login
# ============================================================

@auth_bp.route("/report", methods=["GET", "POST"])
def report():
    if request.method == "GET":
        return render_template("report.html", submitted=False, error=None)

    serial_number = request.form.get("serial_number", "").strip()
    description = request.form.get("description", "").strip()

    if not serial_number or not description:
        return render_template(
            "report.html", submitted=False,
            error="Serial number and description are both required.",
        )

    db.run(
        "INSERT INTO reports (at, serial_number, description) VALUES (:at, :serial, :text)",
        at=datetime.now().strftime("%Y-%m-%d %H:%M"), serial=serial_number, text=description,
    )

    log("public report received", target=serial_number, detail=description[:200])

    return render_template("report.html", submitted=True, error=None)


# ============================================================
# OFFICER DASHBOARD
# ============================================================

@auth_bp.route("/dashboard")
@role_required("lab_officer", "district_officer", "admin")
def dashboard():
    today = date.today()
    cutoff = today + timedelta(days=60)

    cert_rows = db.fetch_all("""
        SELECT id, serial_number, owner_name, instrument_type, expiry_date
        FROM certificates
        ORDER BY expiry_date ASC
    """)

    due, expired = [], []

    for row in cert_rows:
        try:
            expiry = datetime.strptime(row.expiry_date, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            continue

        item = dict(row._mapping)
        item["days"] = (expiry - today).days

        if expiry < today:
            expired.append(item)
        elif expiry <= cutoff:
            due.append(item)

    reports = db.fetch_all("""
        SELECT id, at, serial_number, description, status
        FROM reports
        ORDER BY at DESC
    """)

    # Krishna's rules (fraud.py) write into this table at the moment a
    # certificate is issued. We just read them out here.
    try:
        fraud_alerts = db.fetch_all(
            """SELECT id, at, certificate_code, serial_number, officer_name,
                      reason, status
               FROM fraud_alerts ORDER BY id DESC LIMIT 50"""
        )
    except SQLAlchemyError:
        fraud_alerts = []      # table not made yet - don't kill the page

    return render_template(
        "dashboard.html",
        due=due,
        expired=expired,
        reports=reports,
        fraud_alerts=fraud_alerts,
        user=current_user(),
    )


# ============================================================
# ADMIN — AUDIT LOG
# ============================================================

@auth_bp.route("/admin/audit")
@role_required("admin")
def audit_log():
    entries = db.fetch_all("""
        SELECT at, actor_name, action, target, detail
        FROM audit
        ORDER BY id DESC
        LIMIT 200
    """)

    return render_template("audit.html", entries=entries)