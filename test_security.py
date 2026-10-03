"""
test_security.py - the attacks we tried against our own app, kept as tests
so a later change cannot quietly reopen them.
"""

import importlib

from conftest import PW, issue_code, login, post, q, status_of

POST_ROUTES = ("/login", "/report", "/submit", "/logout", "/revoke/SD-2222-2222")


# ---------------------------------------------------------------- CSRF (SYS-506)
def test_every_form_post_without_a_token_is_refused(app_client):
    login(app_client, "admin1")
    for path in POST_ROUTES:
        r = app_client.post(path, data={"username": "lab1", "password": PW})
        assert r.status_code == 400 and b"SYS-506" in r.data, path


def test_a_token_from_another_session_is_refused(app_client):
    login(app_client)
    r = app_client.post("/submit", data={"csrf_token": "stolen-from-elsewhere", "serial_number": "X"})
    assert r.status_code == 400
    assert q("SELECT COUNT(*) FROM certificates")[0][0] == 0


# ---------------------------------------------------------------- XSS
def test_script_in_a_field_is_shown_as_text_not_run(app_client):
    login(app_client)
    code = issue_code(app_client, owner='<script>alert(1)</script>"><img src=x onerror=alert(2)>')
    body = status_of(app_client, code)[1]
    assert "<script>alert(1)</script>" not in body and "onerror=alert(2)>" not in body
    assert "&lt;script&gt;" in body


def test_script_in_a_search_is_shown_as_text(app_client):
    body = app_client.get('/verify?code=<script>alert(1)</script>').get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body


def test_script_in_a_public_report_is_escaped_on_the_dashboard(app_client):
    post(app_client, "/report", {"serial_number": "X-1", "description": "<b onmouseover=alert(1)>hi</b>"})
    login(app_client)
    body = app_client.get("/dashboard").get_data(as_text=True)
    assert "<b onmouseover" not in body


# ---------------------------------------------------------------- SQL injection
def test_sql_injection_in_login_and_search_does_nothing(app_client):
    for attempt in ("' OR '1'='1", "lab1'--", "x'; DROP TABLE users; --"):
        assert login(app_client, attempt, attempt).status_code == 401
        assert app_client.get(f"/verify?code={attempt}").status_code in (200, 302)
    assert q("SELECT COUNT(*) FROM users")[0][0] >= 4


# ---------------------------------------------------------------- brute force (SYS-505)
def test_login_is_rate_limited(app_client):
    codes = [login(app_client, "lab1", "wrong").status_code for _ in range(12)]
    assert codes[:10] == [401] * 10 and codes[10] == 429


def test_public_reports_are_rate_limited(app_client):
    codes = [post(app_client, "/report", {"serial_number": "S", "description": "spam"}).status_code
             for _ in range(7)]
    assert codes[:5] == [200] * 5 and 429 in codes[5:]
    assert q("SELECT COUNT(*) FROM reports")[0][0] == 5


def test_rate_limit_page_says_what_happened(app_client):
    for _ in range(11):
        r = login(app_client, "lab1", "wrong")
    assert r.status_code == 429 and b"SYS-505" in r.data


# ---------------------------------------------------------------- sessions
def test_login_starts_a_fresh_session(app_client):
    """Session fixation: nothing an attacker planted before login survives it."""
    with app_client.session_transaction() as s:
        s["planted"] = "by attacker"
    login(app_client)
    with app_client.session_transaction() as s:
        assert "planted" not in s and s["username"] == "lab1"


def test_forged_session_cookie_is_rejected(app_client):
    app_client.set_cookie("session", "eyJyb2xlIjoiYWRtaW4iLCJ1c2VyX2lkIjo0fQ.forged.signature")
    assert app_client.get("/admin/audit").status_code == 302


def test_production_cookie_is_secure_httponly_and_lax(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "test-only")
    monkeypatch.setenv("SIGNING_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    monkeypatch.setenv("PW_LAB", "a-real-password")
    import app1
    importlib.reload(app1)
    cfg = app1.app.config
    assert cfg["SESSION_COOKIE_SECURE"] and cfg["SESSION_COOKIE_HTTPONLY"]
    assert cfg["SESSION_COOKIE_SAMESITE"] == "Lax"
    monkeypatch.delenv("APP_ENV")
    from conftest import drop_db
    drop_db()


# ---------------------------------------------------------------- headers and errors
def test_security_headers_on_every_page(app_client):
    r = app_client.get("/")
    h = r.headers
    assert "script-src 'self'" in h["Content-Security-Policy"] and "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY" and h["X-Content-Type-Options"] == "nosniff"
    assert len(h["X-Request-ID"]) >= 8


def test_no_page_uses_inline_script_or_style(app_client):
    """The CSP forbids them; one left behind would silently break in browsers."""
    login(app_client, "admin1")
    code = issue_code(app_client)
    for path in ("/", "/report", "/offline", f"/verify/{code}", f"/certificate/{code}",
                 "/dashboard", "/issue", "/reminders", "/admin/audit", "/admin/health", "/info/help"):
        body = app_client.get(path).get_data(as_text=True)
        assert "<script>" not in body and " style=" not in body and " onclick=" not in body, path


def test_request_id_from_outside_is_reused_only_if_sane(app_client):
    assert app_client.get("/", headers={"X-Request-ID": "abcdef123456"}).headers["X-Request-ID"] == "abcdef123456"
    bad = app_client.get("/", headers={"X-Request-ID": "<script>alert(1)</script>"}).headers["X-Request-ID"]
    assert "<" not in bad


def test_SYS509_unknown_page_shows_code_and_reference(app_client):
    r = app_client.get("/no-such-page")
    assert r.status_code == 404 and b"SYS-509" in r.data and r.headers["X-Request-ID"].encode() in r.data


def test_SYS513_wrong_method(app_client):
    assert app_client.get("/submit").status_code == 405


def test_SYS512_oversized_post_is_refused(app_client):
    r = app_client.post("/report", data={"description": "x" * 100_000})
    assert r.status_code == 413


def test_SYS510_crash_shows_a_reference_not_a_traceback(app_client):
    import app1

    def boom():
        raise RuntimeError("secret internal detail")
    app1.app.add_url_rule("/_boom", "boom", boom)
    r = app_client.get("/_boom")
    assert r.status_code == 500 and b"SYS-510" in r.data
    assert b"secret internal detail" not in r.data and b"Traceback" not in r.data


def test_status_pages_are_not_cached_by_shared_caches(app_client):
    login(app_client)
    code = issue_code(app_client)
    assert "no-store" in app_client.get(f"/verify/{code}").headers.get("Cache-Control", "")


# ---------------------------------------------------------------- enumeration and redirects
def test_certificates_cannot_be_listed_by_counting(app_client):
    login(app_client)
    issue_code(app_client)
    for n in range(1, 6):
        assert status_of(app_client, f"CERT-{n:04d}")[0] == "NOT FOUND"


def test_login_never_redirects_to_another_website(app_client):
    for bad in ("https://evil.example", "//evil.example", "/\\evil.example"):
        r = post(app_client, f"/login?next={bad}", {"username": "lab1", "password": PW})
        assert r.headers["Location"].endswith("/dashboard"), bad
    r = post(app_client, "/login?next=/reminders", {"username": "lab1", "password": PW})
    assert r.headers["Location"].endswith("/reminders")


def test_qr_points_at_the_configured_address_not_the_request_host(app_client):
    """Host-header injection must not make a certificate's QR point elsewhere."""
    login(app_client)
    code = issue_code(app_client)
    body = app_client.get(f"/certificate/{code}", headers={"Host": "evil.example"}).get_data(as_text=True)
    assert "evil.example" not in body


def test_head_requests_never_count_as_a_login_or_a_report(app_client):
    """Link checkers send HEAD; it must not log a failed login or use up the limit."""
    for _ in range(12):
        assert app_client.head("/login").status_code == 200
        assert app_client.head("/report").status_code == 200
    assert q("SELECT COUNT(*) FROM audit WHERE action = 'failed login'")[0][0] == 0
    assert login(app_client).status_code == 302
