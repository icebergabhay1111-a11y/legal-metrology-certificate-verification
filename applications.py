"""
applications.py - traders ask for verification; officers act on the request.

  /my                      a trader's certificates (status today) and requests
  /apply                   a trader asks for an instrument to be verified
  /applications/<ref>/...  an officer declines; issuing goes through /issue

An application never becomes a certificate by itself: an officer still has
to verify the instrument and issue through the normal form, which is then
filled in from the application.
"""

import re

from flask import Blueprint, abort, redirect, render_template, request, url_for

import certs
import clock
import config
import db
import security
from auth import current_user, log, role_required

bp = Blueprint("applications", __name__)
OFFICERS = ("lab_officer", "district_officer", "admin")
BAD_CHARS = re.compile(r"[|\x00-\x1f\x7f]")
LIMITS = {"serial_number": 40, "address": 200, "note": 500}


@bp.route("/my")
@role_required("trader")
def mine():
    """The trader's own page: their firm's certificates and their requests."""
    user = current_user()
    rows = certs.for_firm(user["firm_name"])
    requests_ = db.fetch_all("SELECT * FROM applications WHERE trader_id = :t ORDER BY id DESC", t=user["id"])
    due = [r for r, a in rows if a["status"] in ("EXPIRING SOON", "EXPIRED")]
    return render_template("my.html", rows=rows, requests=requests_, due_count=len(due),
                           user=user, active="my")


def _form_values(form, user):
    """Clean the request form. Returns (values, {field: message})."""
    values = {name: " ".join(form.get(name, "").split()) for name in
              ("serial_number", "instrument_type", "state_code", "jurisdiction", "address", "note")}
    values["serial_number"] = certs.normalise_serial(values["serial_number"])
    values["state_code"] = values["state_code"].upper() or user.get("state_code") or config.DEFAULT_STATE
    problems = {}
    for name, limit in LIMITS.items():
        if len(values[name]) > limit:
            problems[name] = f"Use at most {limit} characters."
        elif BAD_CHARS.search(values[name]):
            problems[name] = "The character | and control characters are not allowed."
    if not values["serial_number"]:
        problems["serial_number"] = "Serial number is required. It is on the instrument's plate."
    if values["state_code"] not in config.STATES:
        problems["state_code"] = "Choose a State from the list."
    elif values["instrument_type"] not in dict(config.instrument_types(values["state_code"])):
        problems["instrument_type"] = "Choose the type of instrument."
    places = config.jurisdictions(values["state_code"])
    if places and values["jurisdiction"] not in places:
        problems["jurisdiction"] = "Choose the district where the instrument is."
    if not values["address"]:
        problems["address"] = "Give the address where the officer should come."
    return values, problems


@bp.route("/apply", methods=["GET", "POST"])
@role_required("trader")
def apply():
    """Request verification or re-verification of one instrument."""
    user = current_user()
    if request.method != "POST":
        picked = request.args.get("state_code", "").upper()
        state_code = picked if picked in config.STATES else (user.get("state_code") or config.DEFAULT_STATE)
        values = {"serial_number": certs.normalise_serial(request.args.get("serial", ""))[:40],
                  "instrument_type": request.args.get("type", "")[:60]}
        return _render_apply(state_code, values, {})
    security.rate_limit("apply")
    values, problems = _form_values(request.form, user)
    if problems:
        return _render_apply(values["state_code"], values, problems, 400)
    reference = "A-" + certs.new_code()[3:]
    db.run("""INSERT INTO applications (reference, created_at, trader_id, firm_name, serial_number,
                  instrument_type, state_code, jurisdiction, address, note)
              VALUES (:ref, :at, :t, :firm, :serial, :itype, :state, :place, :addr, :note)""",
           ref=reference, at=clock.stamp(), t=user["id"], firm=user["firm_name"],
           serial=values["serial_number"], itype=values["instrument_type"], state=values["state_code"],
           place=values["jurisdiction"], addr=values["address"], note=values["note"])
    log("verification requested", target=reference, detail=f"serial {values['serial_number']}")
    return redirect(url_for("applications.mine", sent=reference))


def _render_apply(state_code, values, problems, status=200):
    """The request form, keeping what was typed."""
    return render_template(
        "apply.html", states=config.state_choices(), selected_state=state_code,
        instrument_types=config.instrument_types(state_code), jurisdictions=config.jurisdictions(state_code),
        values=values, problems=problems, user=current_user(), active="apply"), status


def _find(reference):
    """An application by its reference, or None."""
    return db.fetch_one("SELECT * FROM applications WHERE reference = :r", r=(reference or "")[:20])


def _officer_may_act(user, app_row):
    """Officers act on applications from their own State; admins on any."""
    scope = certs.scope_for(user)
    return app_row is not None and app_row.status == "submitted" and (scope is None or scope == app_row.state_code)


def prefill(reference, user):
    """Issue-form values from an open application, if this officer may act on it."""
    if not reference:
        return None
    row = _find(reference)
    if not _officer_may_act(user, row):
        return None
    return {"serial_number": row.serial_number, "owner_name": row.firm_name,
            "instrument_type": row.instrument_type, "state_code": row.state_code,
            "jurisdiction": row.jurisdiction or "", "application": row.reference,
            "address": row.address or "", "note": row.note or ""}


def mark_issued(reference, code, officer):
    """Close an application once its certificate has been issued."""
    row = _find(reference)
    if not _officer_may_act(officer, row):
        return
    db.run("UPDATE applications SET status = 'issued', certificate_code = :c, decided_by = :by, "
           "decided_at = :at WHERE reference = :r AND status = 'submitted'",
           c=code, by=officer["full_name"], at=clock.stamp(), r=reference)
    log("application completed", target=reference, detail=f"certificate {code}")


@bp.route("/applications/<reference>/decline", methods=["POST"])
@role_required(*OFFICERS)
def decline(reference):
    """Turn down a request, with a reason the trader will see."""
    user = current_user()
    row = _find(reference)
    if row is None:
        abort(404)
    if not _officer_may_act(user, row):
        abort(403)
    reason = " ".join(request.form.get("reason", "").split())[:300]
    if len(reason) < 5:
        return redirect(url_for("auth.dashboard", decline_error=reference) + "#applications")
    db.run("UPDATE applications SET status = 'declined', decided_by = :by, decided_at = :at, "
           "decision_note = :why WHERE reference = :r AND status = 'submitted'",
           by=user["full_name"], at=clock.stamp(), why=reason, r=reference)
    log("application declined", target=reference, detail=reason)
    return redirect(url_for("auth.dashboard") + "#applications")
