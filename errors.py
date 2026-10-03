"""
errors.py - every error the system can show, with a stable code.

LM- codes are domain results: the system correctly reporting something
wrong in the real world (an expired certificate, a suspicious issue).
SYS- codes are the software or the request failing. Codes never change
meaning once used, so an officer can quote one on the phone and a log
search finds every case. Full reasoning: 05_scale_up_plan/02_error_taxonomy.md.

Codes for features that do not exist yet (LM-106 suspension, LM-205 GATC
approval lapse, LM-304 fee, LM-305 model approval, SYS-508 uploads) are
deliberately absent: a code should describe something the system does.
LM-106 stays reserved for suspension, as the taxonomy document assigns it.
"""

import logging
import time
import traceback

from flask import g, render_template, request
from werkzeug.exceptions import HTTPException

log = logging.getLogger("sahidaam")

# code -> (title, plain message for the person reading the page)
CODES = {
    # status of a certificate
    "LM-101": ("Not found", "No certificate with this ID exists in this system."),
    "LM-102": ("Expired", "This instrument must not be used in trade until it is re-verified."),
    "LM-103": ("Expiring soon", "The certificate is inside its State's re-verification window."),
    "LM-104": ("Not verified", "This record was not signed, or a field was changed after issue."),
    "LM-105": ("Revoked", "An officer has withdrawn this certificate."),
    "LM-107": ("Unreadable record", "The stored expiry date cannot be read. Treat the record as unreliable."),
    # raised by the fraud checks at the moment of issue
    "LM-201": ("Same serial, different owner", "This serial is already certified to another owner."),
    "LM-202": ("Outside jurisdiction", "Issued for an area outside the issuer's jurisdiction."),
    "LM-203": ("Test centre outside its State", "A test centre may verify only in the State it is approved for."),
    "LM-204": ("Test centre category not approved", "The test centre is not approved for this instrument category."),
    "LM-206": ("Improbable daily volume", "More certificates in a day than one officer can physically verify."),
    "LM-207": ("Re-registered without re-verification", "A lapsed instrument moved to a new owner without being re-verified."),
    # rejected when issuing
    "LM-301": ("Date in the future", "The verification date cannot be in the future."),
    "LM-302": ("Instrument type unknown", "This instrument type is not configured for the selected State."),
    "LM-303": ("State not configured", "This State is not yet on the system."),
    "LM-306": ("Missing or invalid field", "A required field is missing or not valid."),
    # the software or the request
    "SYS-501": ("Service unavailable", "The service is temporarily unavailable. Please try again in a few minutes."),
    "SYS-502": ("Signing key missing", "The signing key is not configured."),
    "SYS-503": ("State settings unreadable", "A State's settings file could not be read."),
    "SYS-504": ("QR code failed", "The certificate was saved but its QR code could not be drawn. Reload the page."),
    "SYS-505": ("Too many requests", "Too many requests from your connection. Please wait a minute and try again."),
    "SYS-506": ("Form expired", "This form has expired or was sent from another page. Go back, reload it and try again."),
    "SYS-507": ("Not allowed", "Your account does not have access to this page."),
    "SYS-509": ("Page not found", "There is no page at this address."),
    "SYS-510": ("Something failed on our side", "Something failed on our side. If you contact us, quote the reference below."),
    "SYS-512": ("Request too large", "What you sent is larger than this form accepts."),
    "SYS-513": ("Method not allowed", "This page cannot be used that way."),
}

# HTTP status -> SYS code used when Flask raises it
HTTP_CODES = {400: "SYS-506", 403: "SYS-507", 404: "SYS-509", 405: "SYS-513",
              413: "SYS-512", 429: "SYS-505", 500: "SYS-510", 503: "SYS-501"}


def title(code):
    """Short title for a code, e.g. 'Expired'."""
    return CODES[code][0]


def message(code):
    """The plain sentence shown to the reader."""
    return CODES[code][1]


def render_error(code, status):
    """The one error page: code, plain message, and the request id to quote."""
    return render_template("error.html", code=code, title=title(code),
                           message=message(code), status=status), status


def init_app(app):
    """Route every HTTP error through render_error and log each request."""
    def handle_http(err):
        status = getattr(err, "code", 500) or 500
        description = getattr(err, "description", "") or ""
        code = description if description in CODES else HTTP_CODES.get(status, "SYS-510")
        if status == 429:
            log.warning("rate limit rid=%s ip=%s path=%s", g.get("request_id"), request.remote_addr, request.path)
        return render_error(code, status)

    def handle_crash(err):
        if isinstance(err, HTTPException):
            return handle_http(err)
        log.error("SYS-510 rid=%s path=%s\n%s", g.get("request_id"), request.path, traceback.format_exc())
        return render_error("SYS-510", 500)

    for status in HTTP_CODES:
        app.register_error_handler(status, handle_http)
    app.register_error_handler(Exception, handle_crash)
    app.after_request(_log_request)


def _log_request(response):
    """One line per request: id, method, path, status, milliseconds."""
    started = g.get("started")
    ms = round((time.perf_counter() - started) * 1000) if started else -1
    log.info("rid=%s %s %s %s %sms", g.get("request_id"), request.method, request.path, response.status_code, ms)
    return response
