"""
certs.py - one place that decides a certificate's status.

The status page, the officer dashboard and the re-verification list all
call these functions, so they can never disagree. Each State sets its own
"due soon" window in states/XX.json (reminder_window_days).
"""

from datetime import datetime

import clock
import config
import db


def code_for(cert_id):
    """Printed certificate ID, e.g. 7 -> 'CERT-0007'."""
    return f"CERT-{cert_id:04d}"


def parse_date(text):
    """'2026-10-02' -> date, or None if the stored text is unreadable."""
    try:
        return datetime.strptime(str(text).strip(), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def status_on(expiry, state_code, today):
    """('EXPIRED', days since) / ('EXPIRING SOON', days left) / ('VALID', days left)."""
    if expiry < today:
        return "EXPIRED", (today - expiry).days
    days_left = (expiry - today).days
    if days_left <= config.reminder_days(state_code):
        return "EXPIRING SOON", days_left
    return "VALID", days_left


def due_and_expired():
    """Officer lists: (due within their State's window, already expired)."""
    today = clock.today()
    rows = db.fetch_all("""
        SELECT id, serial_number, owner_name, instrument_type, expiry_date, state_code
        FROM certificates
        ORDER BY expiry_date ASC
    """)
    due, expired = [], []
    for row in rows:
        expiry = parse_date(row.expiry_date)
        if expiry is None:
            continue
        status, days = status_on(expiry, row.state_code, today)
        item = {
            "code": code_for(row.id), "serial_number": row.serial_number,
            "owner_name": row.owner_name, "instrument_type": row.instrument_type,
            "expires_on": row.expiry_date, "days": days, "state_code": row.state_code,
        }
        if status == "EXPIRED":
            expired.append(item)
        elif status == "EXPIRING SOON":
            due.append(item)
    return due, expired
