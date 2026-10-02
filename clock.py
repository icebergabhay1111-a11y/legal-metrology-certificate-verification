"""
clock.py - the date and time in India, whatever timezone the server runs in.

Render's servers run on UTC. Without this, between midnight and 05:30 IST
the status page would use yesterday's date, so a certificate could read
VALID on the morning it actually expired. India has no daylight saving,
so a fixed +05:30 offset is exact and needs no timezone database.
"""

from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30), "IST")


def now():
    """Current date and time in India."""
    return datetime.now(IST)


def today():
    """Today's date in India - use this, never date.today()."""
    return now().date()


def stamp():
    """Timestamp for audit and alert rows, e.g. '2026-10-02 14:05 IST'."""
    return now().strftime("%Y-%m-%d %H:%M IST")
