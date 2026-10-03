"""
config.py - loads one JSON file per State, so nothing State-specific
sits in the Python code.

Owner: Anikeit (26BDE0124) + Krishna (26BDE0134)

WHY: Act s.53(2)(c) and (d) put the verification/stamping fee, and the
jurisdiction + licence period, in the hands of EACH State Government.
So the same engine has to behave differently per State. Adding a 4th
State = drop a new file in states/. No code change. That's our answer
to "how do u scale to 36".

Also loads enforcement.json (Shreyash's file) - the section + penalty
we show an officer when something is wrong.
"""

import json
import os
from datetime import datetime

import clock

STATES_DIR = "states"
ENFORCEMENT_FILE = "enforcement.json"

# Fallback used only if a State file is missing a value. Same numbers
# we've always used. Held as UNVERIFIED - see note below.
DEFAULT_MONTHS = {
    "Weight": 24, "Capacity measure": 24, "Length measure": 24,
    "Measuring tape": 24, "Beam scale": 24, "Counter machine": 24,
    "Storage tank": 60, "Electronic weighing instrument": 12,
    "Weighbridge": 12, "Fuel dispensing unit": 12,
    "Automatic weighing instrument": 12, "Other instrument": 12,
}

PERIOD_NOTE = (
    "Re-verification periods follow rule 27(2), Legal Metrology (General) "
    "Rules, 2011. Held as unverified: corroborated by secondary "
    "publications, not yet read in the gazette. Configurable per State."
)


STATE_ERRORS = []      # file names that failed to load (SYS-503), shown on /admin/health


def _load_states():
    """Read every states/XX.json. A broken file is skipped and recorded."""
    out = {}
    if not os.path.isdir(STATES_DIR):
        return out
    for name in sorted(os.listdir(STATES_DIR)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(STATES_DIR, name), encoding="utf-8") as f:
                cfg = json.load(f)
            out[cfg["state_code"].upper()] = cfg
        except (OSError, ValueError, KeyError):
            # A broken config file must never take the whole app down,
            # but it must be visible: SYS-503 on the admin health page.
            STATE_ERRORS.append(name)
            continue
    return out


STATES = _load_states()
DEFAULT_STATE = "TN" if "TN" in STATES else (next(iter(STATES), "TN"))


def state(code):
    """Config for a State code. Falls back to the default State."""
    return STATES.get((code or "").upper(), STATES.get(DEFAULT_STATE, {}))


def months_for(state_code, instrument_type):
    """How many months this instrument is good for, in this State."""
    cfg = state(state_code)
    table = cfg.get("reverification_months") or DEFAULT_MONTHS
    return table.get(instrument_type, DEFAULT_MONTHS.get(instrument_type, 12))


def instrument_types(state_code=None):
    """Instrument list for the dropdown, shortest period first."""
    cfg = state(state_code)
    table = cfg.get("reverification_months") or DEFAULT_MONTHS
    return sorted(table.items(), key=lambda kv: (kv[1], kv[0]))


def fee_for(state_code, instrument_type):
    """Verification fee in rupees, or None if this State hasn't set one."""
    return (state(state_code).get("fees_inr") or {}).get(instrument_type)


def reminder_days(state_code):
    return int(state(state_code).get("reminder_window_days", 60))


def reminder_windows():
    """[(State name, days)] - each State's 'due soon' window, for display."""
    return sorted((s.get("state_name", c), reminder_days(c)) for c, s in STATES.items())


def daily_limit(state_code):
    return int(state(state_code).get("daily_issue_limit", 40))


def state_choices():
    """[(code, name)] for the State dropdown."""
    return sorted((c, s.get("state_name", c)) for c, s in STATES.items())


# ------------------------------------------------------------------
# ENFORCEMENT - what the law says when something is wrong
# ------------------------------------------------------------------

def _load_enforcement():
    for path in (ENFORCEMENT_FILE, os.path.join("SIH3", ENFORCEMENT_FILE)):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            continue
    return []


ENFORCEMENT = _load_enforcement()


def enforcement_for(situation_keyword):
    """Find the enforcement entry whose situation mentions this word."""
    kw = situation_keyword.lower()
    for entry in ENFORCEMENT:
        if kw in (entry.get("situation") or "").lower():
            return entry
    return None


def jurisdictions(state_code):
    """Districts an instrument can be in, for this State. [] if not configured."""
    return list(state(state_code).get("jurisdictions") or [])


# ------------------------------------------------------------------
# CONTACTS - every number carries where it came from and when it was checked
# ------------------------------------------------------------------

def _load_national():
    """National contacts (NCH 1915, Legal Metrology Division) from contacts_national.json."""
    try:
        with open("contacts_national.json", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


NATIONAL_CONTACTS = _load_national()


def is_sourced(entry):
    """A contact may be shown only if it says where it came from and when."""
    return bool((entry.get("source") or "").strip() and (entry.get("verified_on") or "").strip())


def has_details(entry):
    """True if the entry holds a phone, email, address or link."""
    return any((entry.get(k) or "").strip() for k in ("phone", "email", "url", "address"))


def contacts_for(state_code):
    """Sourced contacts for this State. An empty entry shows nothing at all."""
    entries = (state(state_code).get("contacts") or []) if state_code else []
    return [e for e in entries if has_details(e) and is_sourced(e)]


def state_contacts():
    """[(State name, [sourced contacts])] for the help page."""
    return [(s.get("state_name", c), contacts_for(c)) for c, s in sorted(STATES.items())]


def stale_contacts(max_age_days=180):
    """Contact labels whose verified_on date is older than max_age_days."""
    out = []
    every = list(NATIONAL_CONTACTS)
    for cfg in STATES.values():
        every.extend(cfg.get("contacts") or [])
    for entry in every:
        try:
            checked = datetime.strptime(entry.get("verified_on", ""), "%Y-%m-%d").date()
        except ValueError:
            continue
        if (clock.today() - checked).days > max_age_days:
            out.append(entry.get("label", "?"))
    return out
