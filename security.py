"""
security.py - protections every request passes through.

  * request id  - every response carries X-Request-ID; errors show it
  * CSRF        - every form POST must carry the token from its own page
  * headers     - CSP, no framing, no MIME sniffing, strict referrer
  * rate limits - per client IP, in memory (see the note on limits below)
  * cookies     - HttpOnly, SameSite=Lax, Secure in production

Kept dependency-free on purpose: each piece is a few lines and can be read
in one sitting. Note on rate limits: the counters live in this process's
memory, which is right for one gunicorn worker (Render free runs one).
With several workers or servers they would need a shared store.
"""

import hmac
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque

from flask import abort, g, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

CSRF_FIELD = "csrf_token"

# Content-Security-Policy: only our own scripts and styles; images may be
# data: URIs because the certificate QR is one. No inline script at all.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; "
       "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
       "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

# bucket name -> (max requests, per this many seconds)
LIMITS = {
    "login": (10, 300),     # 10 attempts per 5 minutes per IP
    "report": (5, 600),     # 5 public reports per 10 minutes per IP
    "lookup": (120, 60),    # status checks and searches
    "issue": (60, 60),
}

_hits = defaultdict(deque)
_hits_lock = threading.Lock()


def init_app(app, production):
    """Attach every protection in this file to the Flask app."""
    # Render puts one proxy in front of us; trust exactly one X-Forwarded-For hop.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=production,
        PERMANENT_SESSION_LIFETIME=8 * 3600,     # an officer's working day
        MAX_CONTENT_LENGTH=64 * 1024,            # no form here needs more
    )
    app.before_request(_start_request)
    app.before_request(_check_csrf)
    app.after_request(_add_headers)
    app.jinja_env.globals["csrf_token"] = csrf_token


def _start_request():
    """Give the request an id (reuse a sane one from the proxy) and a start time."""
    incoming = request.headers.get("X-Request-ID", "")
    ok = 8 <= len(incoming) <= 64 and incoming.replace("-", "").isalnum()
    g.request_id = incoming if ok else uuid.uuid4().hex[:12]
    g.started = time.perf_counter()


def csrf_token():
    """The per-session token that forms must send back. Made on first use."""
    if CSRF_FIELD not in session:
        session[CSRF_FIELD] = secrets.token_urlsafe(32)
    return session[CSRF_FIELD]


def _check_csrf():
    """Refuse a POST whose token does not match this session's token."""
    if request.method != "POST":
        return None
    sent = request.form.get(CSRF_FIELD, "")
    expected = session.get(CSRF_FIELD, "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, description="SYS-506")
    return None


def _add_headers(response):
    """Security headers and the request id on every response."""
    response.headers["X-Request-ID"] = g.get("request_id", "-")
    response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(self), geolocation=(), microphone=()"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    if g.get("no_store"):
        response.headers["Cache-Control"] = "no-store"
    return response


def rate_limit(bucket):
    """Abort with 429 when this client IP has used up the bucket's allowance."""
    allowed, window = LIMITS[bucket]
    key = (bucket, request.remote_addr or "?")
    now = time.monotonic()
    with _hits_lock:
        if len(_hits) > 5000:
            _sweep(now)
        hits = _hits[key]
        while hits and now - hits[0] > window:
            hits.popleft()
        if len(hits) >= allowed:
            abort(429)
        hits.append(now)


def _sweep(now):
    """Drop counters with no recent hits, so memory cannot grow without bound."""
    longest = max(window for _, window in LIMITS.values())
    for key in list(_hits):
        if not _hits[key] or now - _hits[key][-1] > longest:
            del _hits[key]


def reset_rate_limits():
    """Forget every counter. Used by the tests."""
    with _hits_lock:
        _hits.clear()
