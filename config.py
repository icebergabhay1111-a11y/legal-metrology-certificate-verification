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


def _load_states():
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
            # A broken config file must never take the whole app down.
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
