"""
auth.py - login, the four roles, the audit log, the dashboard and public reports.

Original owner: Abhay (26BDE0132).

DEMO ACCOUNTS
Render's free disk is wiped on every deploy, so the demo logins are made
again at every start (skipped if they already exist, so a real password
is never overwritten). Each account's password comes from its own
environment variable (PW_TRADER, PW_LAB, PW_DISTRICT, PW_ADMIN, PW_MZ).
Locally a known demo password is used; with APP_ENV=production an account
whose variable is missing is not created at all.

AUDIT LOG
Every action goes through log(). Each row stores a hash of itself and of
the row before it, so deleting or editing a past row breaks the chain and
the audit page says where.
"""

import functools
import hashlib
import os
import secrets

from flask import Blueprint, abort, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import certs
import clock
import config
import db
import security

ROLES = ("trader", "lab_officer", "district_officer", "admin")
OFFICERS = ("lab_officer", "district_officer", "admin")

auth_bp = Blueprint("auth", __name__)

DEMO_USERS = [
    # username, env var for pw, full name, role, State, jurisdiction ("" = whole State), firm (traders)
    ("trader1",   "PW_TRADER",   "Ramesh Trader",           "trader",           "TN", "Chennai", "Sharma Weighbridge Co. (sample)"),
    ("lab1",      "PW_LAB",      "Priya Lab Officer",       "lab_officer",      "TN", "Chennai", ""),
    ("district1", "PW_DISTRICT", "Suresh District Officer", "district_officer", "TN", "Chennai", ""),
    ("admin1",    "PW_ADMIN",    "Admin User",              "admin",            "TN", "",        ""),
    ("mz1",       "PW_MZ",       "Lalrin Lab Officer",      "lab_officer",      "MZ", "Aizawl",  ""),
]

# One demo officer per team member, each in a different State. They share
# one password, from TEAM_PASSWORD (in production the accounts are not made
# without it). First names only, marked "demo", so no one reads them as
# real Government officers.
TEAM_OFFICERS = [
    ("anikeit",  "Anikeit (demo officer)",  "TN", "Madurai"),
    ("abhay",    "Abhay (demo officer)",    "MH", "Pune"),
    ("anvita",   "Anvita (demo officer)",   "KA", "Bengaluru Urban"),
    ("krishna",  "Krishna (demo officer)",  "GJ", "Ahmedabad"),
    ("shreyash", "Shreyash (demo officer)", "UP", "Lucknow"),
    ("vaibhavi", "Vaibhavi (demo officer)", "KL", "Ernakulam"),
]
DEFAULT_DEMO_PASSWORD = "sahidaam2026"

# Checked when the username does not exist, so a wrong username takes as
# long as a wrong password and response time does not reveal which it was.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


def ensure_demo_users():
    """Create any missing demo account. Never changes an existing one."""
    accounts = list(DEMO_USERS)
    for username, full_name, state_code, place in TEAM_OFFICERS:
        accounts.append((username, "TEAM_PASSWORD", full_name, "district_officer", state_code, place, ""))
    for username, env_var, full_name, role, state_code, jurisdiction, firm in accounts:
        if db.fetch_one("SELECT id FROM users WHERE username = :u", u=username):
            continue
        password = os.environ.get(env_var)
        if not password and os.environ.get("APP_ENV") == "production":
            # Never fall back to the password printed in public source.
            print(f"WARNING: {env_var} not set - account '{username}' not created.")
            continue
        db.run(
            """INSERT INTO users (username, password_hash, full_name, role, state_code, jurisdiction, firm_name)
               VALUES (:u, :h, :name, :role, :state, :jur, :firm)""",
            u=username, h=generate_password_hash(password or DEFAULT_DEMO_PASSWORD),
            name=full_name, role=role, state=state_code, jur=jurisdiction, firm=firm or None,
        )


# ============================================================
# AUDIT LOG (hash-chained)
# ============================================================

def _row_hash(prev_hash, at, actor_name, action, target, detail):
    """SHA-256 over the previous row's hash and this row's fields."""
    text = "\x1f".join(str(x or "") for x in (prev_hash, at, actor_name, action, target, detail))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def log(action, target="", detail=""):
    """Record one action. The only place that writes to the audit table."""
    actor_id = session.get("user_id")
    actor_name = session.get("full_name", "anonymous")
    at = clock.stamp()
    with db.engine.begin() as conn:
        last = conn.execute(db.text("SELECT row_hash FROM audit ORDER BY id DESC LIMIT 1")).fetchone()
        prev = last[0] if last and last[0] else ""
        conn.execute(db.text(
            """INSERT INTO audit (at, actor_id, actor_name, action, target, detail, prev_hash, row_hash)
               VALUES (:at, :actor_id, :actor_name, :action, :target, :detail, :prev, :hash)"""),
            dict(at=at, actor_id=actor_id, actor_name=actor_name, action=action, target=target,
                 detail=detail, prev=prev,
                 hash=_row_hash(prev, at, actor_name, action, target, detail)))


def check_audit_chain():
    """(True, None) if every row's hash is intact, else (False, first bad row id)."""
    prev = ""
    rows = db.fetch_all("SELECT id, at, actor_name, action, target, detail, prev_hash, row_hash "
                        "FROM audit ORDER BY id")
    for row in rows:
        if row.row_hash is None:          # written before the chain existed
            continue
        expected = _row_hash(prev, row.at, row.actor_name, row.action, row.target, row.detail)
        if row.prev_hash != prev or row.row_hash != expected:
            return False, row.id
        prev = row.row_hash
    return True, None


# ============================================================
# SESSION AND ROLES
# ============================================================

def current_user():
    """Dict for the logged-in user, or None."""
    if "user_id" not in session:
        return None
    return {
        "id": session["user_id"],
        "username": session.get("username"),
        "full_name": session.get("full_name"),
        "role": session.get("role"),
        "state_code": session.get("state_code"),
        "jurisdiction": session.get("jurisdiction") or "",
        "firm_name": session.get("firm_name") or "",
    }


def role_required(*allowed_roles):
    """Route decorator. The server refuses; hiding a button is not a control.

    Not logged in: sent to login (and back afterwards, for a page visit).
    Wrong role: 403, and the attempt is logged - probing is itself a signal.
    """
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if user is None:
                if request.method == "GET":
                    return redirect(url_for("auth.login", next=request.path))
                return redirect(url_for("auth.login"))
            if user["role"] not in allowed_roles:
                log("access refused", target=request.path, detail=f"SYS-507 role {user['role']}")
                return render_template("403.html", role=user["role"]), 403
            g.user = user
            return view(*args, **kwargs)
        return wrapped
    return decorator


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Officer sign-in. Same message and timing for a wrong name or password."""
    if request.method != "POST":       # GET and HEAD just show the form
        return render_template("login.html", error=None)
    security.rate_limit("login")
    username = request.form.get("username", "").strip()[:60]
    password = request.form.get("password", "")[:200]
    row = db.fetch_one("SELECT * FROM users WHERE username = :u", u=username)
    stored_hash = row.password_hash if row else _DUMMY_HASH
    if not check_password_hash(stored_hash, password) or row is None:
        log("failed login", target=username, detail="no such user" if row is None else "wrong password")
        return render_template("login.html", error="Incorrect username or password."), 401
    # A fresh session on every login: nothing set before sign-in survives it.
    session.clear()
    session.permanent = True
    session.update(user_id=row.id, username=row.username, full_name=row.full_name,
                   role=row.role, state_code=row.state_code, jurisdiction=row.jurisdiction or "",
                   firm_name=row.firm_name or "")
    log("login", target=username)
    return redirect(safe_next(request.args.get("next"), row.role))


def safe_next(target, role=None):
    """Only follow ?next= to a page on this site, never to another website.

    With no ?next=, a trader lands on their own page and an officer on the dashboard.
    """
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    if role == "trader":
        return url_for("applications.mine")
    return url_for("auth.dashboard")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Sign out. POST with a CSRF token, so another site cannot sign you out."""
    log("logout", target=session.get("username", ""))
    session.clear()
    return redirect(url_for("home"))


# ============================================================
# PUBLIC REPORT FORM - no login
# ============================================================

@auth_bp.route("/report", methods=["GET", "POST"])
def report():
    """Anyone can report a suspect instrument; they get a reference to quote."""
    if request.method != "POST":       # GET and HEAD just show the form
        return render_template("report.html", submitted=False, error=None, states=config.state_choices())
    security.rate_limit("report")
    serial_number = certs.normalise_serial(request.form.get("serial_number", ""))
    description = " ".join(request.form.get("description", "").split())
    error = None
    if len(description) < 10:
        error = "Describe what you noticed and where, in at least a few words."
    elif len(serial_number) > 40 or len(description) > 2000:
        error = "Keep the serial number under 40 characters and the description under 2,000."
    state_code = request.form.get("state_code", "").upper()
    if state_code and state_code not in config.STATES:
        error = "Choose a State from the list."
    if error:
        return render_template("report.html", submitted=False, error=error, states=config.state_choices()), 400
    if not state_code:
        state_code = _state_of(serial_number)
    reference = "R-" + certs.new_code()[3:]
    db.run("INSERT INTO reports (at, serial_number, description, reference, state_code) "
           "VALUES (:at, :serial, :text, :ref, :state)",
           at=clock.stamp(), serial=serial_number, text=description, ref=reference, state=state_code)
    log("public report received", target=serial_number, detail=f"{reference}: {description[:200]}")
    return render_template("report.html", submitted=True, error=None, reference=reference)


def _state_of(text):
    """The State of the certificate a report names (by ID or serial), or None."""
    if not text:
        return None
    row = certs.find(certs.normalise_code(text))
    if row is None:
        matches = certs.by_serial(text, limit=1)
        row = matches[0][0] if matches else None
    return row.state_code if row else None


# ============================================================
# OFFICER DASHBOARD AND AUDIT LOG
# ============================================================

@auth_bp.route("/dashboard")
@role_required(*OFFICERS)
def dashboard():
    """What needs action first: fraud alerts, expired, due soon, public reports."""
    user = current_user()
    scope = certs.scope_for(user)
    due, expired = certs.due_and_expired(scope)
    pending = applications_for(scope)
    # Open reports for this State, plus any whose State is unknown.
    reports = db.fetch_all(
        "SELECT id, at, serial_number, description, status, reference, state_code FROM reports "
        "WHERE status = 'open' AND (CAST(:state AS TEXT) IS NULL OR state_code = :state OR state_code IS NULL) "
        "ORDER BY id DESC", state=scope)
    fraud_alerts = db.fetch_all(
        "SELECT f.id, f.at, f.code, f.certificate_code, f.serial_number, f.officer_name, f.reason, f.status "
        "FROM fraud_alerts f JOIN certificates c ON c.code = f.certificate_code "
        "WHERE CAST(:state AS TEXT) IS NULL OR c.state_code = :state ORDER BY f.id DESC LIMIT 50", state=scope)
    return render_template("dashboard.html", today=clock.today().isoformat(), due=due,
                           expired=expired, reports=reports, fraud_alerts=fraud_alerts,
                           applications=pending, user=user, scope=scope,
                           state_name=config.state(scope).get("state_name") if scope else None)


@auth_bp.route("/admin/audit")
@role_required("admin")
def audit_log():
    """The last 200 actions, newest first, and whether the hash chain is intact."""
    entries = db.fetch_all("SELECT id, at, actor_name, action, target, detail FROM audit "
                           "ORDER BY id DESC LIMIT 200")
    intact, broken_at = check_audit_chain()
    return render_template("audit.html", entries=entries, intact=intact, broken_at=broken_at)


def applications_for(state_code):
    """Open verification applications for an officer's State (None = all)."""
    return db.fetch_all(
        "SELECT * FROM applications WHERE status = 'submitted' AND "
        "(CAST(:state AS TEXT) IS NULL OR state_code = :state) ORDER BY id", state=state_code)


@auth_bp.route("/reports/<int:report_id>/close", methods=["POST"])
@role_required(*OFFICERS)
def close_report(report_id):
    """Close a public report with what was done, so it leaves the open list."""
    user = current_user()
    row = db.fetch_one("SELECT id, reference, state_code, status FROM reports WHERE id = :i", i=report_id)
    if row is None:
        abort(404)
    scope = certs.scope_for(user)
    if scope is not None and row.state_code not in (None, scope):
        abort(403)
    outcome = " ".join(request.form.get("outcome", "").split())[:300]
    if len(outcome) < 5 or row.status != "open":
        return redirect(url_for("auth.dashboard", close_error=row.reference) + "#reports")
    db.run("UPDATE reports SET status = 'closed', closed_by = :by, closed_at = :at, outcome = :o "
           "WHERE id = :i AND status = 'open'", by=user["full_name"], at=clock.stamp(), o=outcome, i=report_id)
    log("public report closed", target=row.reference, detail=outcome)
    return redirect(url_for("auth.dashboard") + "#reports")
