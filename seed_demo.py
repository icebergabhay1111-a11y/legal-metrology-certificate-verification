"""
seed_demo.py - realistic, deterministic, obviously fake test data.

    python seed_demo.py --reset    wipe the data and generate the full set (~900 certificates)
    python seed_demo.py --demo     wipe the data and create only the four walkthrough certificates
    python seed_demo.py --verify   check the counts per status band and the fraud alerts

Every certificate goes through the same create_certificate() as the issue
form, so signatures, expiry arithmetic and the four fraud rules are the real
ones. Names are invented and marked "(sample)"; no real person, phone number
or address is used. A fixed random seed makes the same certificates every
time (same codes, serials, owners, dates). Officer account ids grow with
each run, so the signatures differ. Dates are relative to today, so the
status bands stay meaningful whenever it is run.

It refuses to run with APP_ENV=production. Against a hosted database
(DATABASE_URL set) it asks you to add --yes, after showing the host.
"""

import os
import random
import sys
from datetime import timedelta
from urllib.parse import urlparse

from flask import session
from werkzeug.security import generate_password_hash



def refuse_unsafe_targets():
    """Never seed production; ask before touching a hosted database.

    Runs before app1 is imported, because importing it already migrates the
    target database and creates the demo accounts there.
    """
    if os.environ.get("APP_ENV") == "production":
        sys.exit("Refusing: APP_ENV=production. Test data never goes into production.")
    url = os.environ.get("DATABASE_URL", "")
    if url and "--yes" not in sys.argv:
        sys.exit(f"DATABASE_URL points at {urlparse(url).hostname}. "
                 "If that is the test database, run again with --yes.")


if __name__ == "__main__" and "--verify" not in sys.argv:
    refuse_unsafe_targets()

import app1     # noqa: E402  (after the safety check, on purpose)
import auth     # noqa: E402
import certs    # noqa: E402
import clock    # noqa: E402
import config   # noqa: E402
import db       # noqa: E402

SEED = 2026
RNG = random.Random(SEED)
SEED_PASSWORD = os.environ.get("SEED_PASSWORD", auth.DEFAULT_DEMO_PASSWORD)

# instrument type -> (serial prefix, weight in the mix)
INSTRUMENTS = {
    "Weighbridge": ("WB", 22), "Fuel dispensing unit": ("FD", 22),
    "Electronic weighing instrument": ("EW", 20), "Counter machine": ("CM", 10),
    "Automatic weighing instrument": ("AW", 8), "Beam scale": ("BS", 6),
    "Weight": ("WT", 6), "Measuring tape": ("MT", 3), "Storage tank": ("ST", 3),
}
FIRST = ["Sagar", "Kaveri", "Lotus", "Nilgiri", "Ganga", "Sunrise", "Pragati", "Vasant", "Annapurna",
         "Coral", "Amber", "Banyan", "Monsoon", "Saffron", "Peacock", "Tulsi", "Harvest", "Lantern"]
TRADE = ["Traders", "Kirana Store", "Fuels", "Weighbridge Co.", "Agro Mart", "Sweets", "Logistics",
         "Rice Mill", "Cold Storage", "Hardware"]
# status band -> (how many, range of days left; negative means expired)
BANDS = {"VALID": (495, (61, 700)), "EXPIRING SOON": (135, (0, 44)),
         "EXPIRED": (180, (-365, -1)), "LONG EXPIRED": (90, (-1500, -366))}
WALKTHROUGH = ["CERT-0001", "CERT-0002", "CERT-0003", "CERT-0004"]


def wipe():
    """Delete every certificate, alert, report and audit row, and seeded officers."""
    with db.engine.begin() as conn:
        for table in ("fraud_alerts", "certificates", "reports", "audit", "applications"):
            conn.execute(db.text(f"DELETE FROM {table}"))
        conn.execute(db.text("DELETE FROM users WHERE username LIKE 'seed\\_%' ESCAPE '\\'"))


def make_officers():
    """A lab officer per district and a district officer per State. Returns their dicts."""
    officers = []
    for state_code, cfg in sorted(config.STATES.items()):
        for n, place in enumerate(cfg.get("jurisdictions", [])):
            officers.append(_officer(f"seed_{state_code.lower()}_lab{n + 1}", f"{place} Lab Officer (sample)",
                                     "lab_officer", state_code, place))
        officers.append(_officer(f"seed_{state_code.lower()}_district", f"{cfg['state_name']} District Officer (sample)",
                                 "district_officer", state_code, ""))
    return officers


def _officer(username, full_name, role, state_code, place):
    """Insert one officer account (or reuse it) and return it in the shape current_user() gives."""
    row = db.fetch_one("SELECT id FROM users WHERE username = :u", u=username)
    if row:
        return {"id": row.id, "username": username, "full_name": full_name, "role": role,
                "state_code": state_code, "jurisdiction": place}
    db.run("INSERT INTO users (username, password_hash, full_name, role, state_code, jurisdiction) "
           "VALUES (:u, :h, :n, :r, :s, :j)", u=username, h=generate_password_hash(SEED_PASSWORD, "pbkdf2"),
           n=full_name, r=role, s=state_code, j=place)
    row = db.fetch_one("SELECT id FROM users WHERE username = :u", u=username)
    return {"id": row.id, "username": username, "full_name": full_name, "role": role,
            "state_code": state_code, "jurisdiction": place}


def seeded_code():
    """A code in the normal SD-XXXX-XXXX form, from the fixed random seed."""
    chars = "".join(RNG.choice(certs.CODE_ALPHABET) for _ in range(8))
    return f"SD-{chars[:4]}-{chars[4:]}"


def issue(officer, serial, owner, itype, verified, place=None, code=None):
    """Issue through the real code path, and write the audit row as that officer."""
    values = {"serial_number": certs.normalise_serial(serial), "owner_name": owner, "instrument_type": itype,
              "instrument_class": RNG.choice(["Class I", "Class II", "Class III", "Class IIII", ""]),
              "max_permissible_error": RNG.choice(["± 1 g", "± 10 g", "± 20 kg", "± 0.5%", ""]),
              "verification_date": verified.isoformat(), "state_code": officer["state_code"],
              "jurisdiction": place or officer["jurisdiction"] or config.jurisdictions(officer["state_code"])[0]}
    code = app1.create_certificate(values, officer, code=code or seeded_code())
    with app1.app.test_request_context():
        session.update(user_id=officer["id"], full_name=officer["full_name"])
        auth.log("certificate issued", target=code, detail=f"seed: serial {values['serial_number']}")
    return code


def verified_for(itype, state_code, days_left):
    """The verification date that makes a certificate have days_left today.

    days_left is capped below the instrument's whole period, so the
    verification date is never in the future (LM-301 applies to seeds too).
    """
    months = config.months_for(state_code, itype)
    today = clock.today()
    longest = (app1.add_months(today, months) - today).days - 1
    days_left = min(days_left, longest)
    expiry = today + timedelta(days=days_left)
    verified = app1.add_months(expiry, -months)
    while app1.add_months(verified, months) < expiry:   # month-end clamping
        verified += timedelta(days=1)
    return verified


def seed_full():
    """~900 certificates in the agreed bands, plus fraud cases and near misses."""
    officers = [o for o in make_officers() if o["role"] == "lab_officer"]
    firms = [f"{RNG.choice(FIRST)} {RNG.choice(TRADE)} (sample)" for _ in range(40)]
    types = list(INSTRUMENTS)
    weights = [INSTRUMENTS[t][1] for t in types]
    serial_no = 1000
    history = []
    edge_days = {"EXPIRING SOON": [0, 1], "EXPIRED": [-1]}     # today, tomorrow, yesterday
    for band, (count, (low, high)) in BANDS.items():
        for i in range(count - (90 if band == "LONG EXPIRED" else 0)):
            serial_no += 1
            officer, itype, owner = RNG.choice(officers), RNG.choices(types, weights)[0], RNG.choice(firms)
            days = edge_days[band][i] if band in edge_days and i < len(edge_days[band]) else RNG.randint(low, high)
            serial = f"{INSTRUMENTS[itype][0]}-{serial_no}"
            verified = verified_for(itype, officer["state_code"], days)
            # Renewal history only for periods up to 24 months, so every older
            # record stays inside the ten-year limit the issue form enforces.
            if band == "VALID" and len(history) < 90 and config.months_for(officer["state_code"], itype) <= 24:
                history.append((officer, serial, owner, itype, verified))
            issue(officer, serial, owner, itype, verified)
    # LONG EXPIRED: the previous certificate of 90 instruments renewed by the same owner.
    for officer, serial, owner, itype, current_verified in history:
        months = config.months_for(officer["state_code"], itype)
        older = app1.add_months(current_verified, -months) - timedelta(days=RNG.randint(400, 900))
        issue(officer, serial, owner, itype, older)
    seed_fraud(officers, firms)
    seed_reports_and_revocations(officers)
    seed_request()


def seed_fraud(officers, firms):
    """At least two of each fraud rule, and near misses that must not fire."""
    tn = [o for o in officers if o["state_code"] == "TN"]
    mz = [o for o in officers if o["state_code"] == "MZ"]
    today = clock.today()
    for n in range(3):          # LM-201: a live serial certified again to a different owner
        issue(tn[0], f"WB-F20{n}", "Kaveri Fuels (sample)", "Weighbridge", today - timedelta(days=30))
        issue(tn[1], f"WB-F20{n}", "Lotus Traders (sample)", "Weighbridge", today - timedelta(days=5))
    for n in range(3):          # LM-202: officer issuing outside their own district
        issue(tn[0], f"EW-F21{n}", RNG.choice(firms), "Electronic weighing instrument",
              today - timedelta(days=10 + n), place="Madurai")
    limit = config.daily_limit("MZ")
    busy_day = today - timedelta(days=3)
    for n in range(limit + 2):  # LM-206: two certificates over the State's daily limit
        issue(mz[0], f"CM-F22{n:02d}", RNG.choice(firms), "Counter machine", busy_day)
    for n in range(2):          # LM-207: lapsed, moved to a new owner, never re-verified
        old = today - timedelta(days=500)
        issue(tn[2], f"FD-F23{n}", "Ganga Fuels (sample)", "Fuel dispensing unit", old)
        issue(tn[2], f"FD-F23{n}", "Monsoon Fuels (sample)", "Fuel dispensing unit", old + timedelta(days=10))
    # Near misses: renewal by the same owner; a sale re-verified after the lapse.
    issue(tn[3], "WB-N300", "Amber Logistics (sample)", "Weighbridge", today - timedelta(days=200))
    issue(tn[3], "WB-N300", "Amber Logistics (sample)", "Weighbridge", today - timedelta(days=2))
    issue(tn[3], "FD-N301", "Coral Fuels (sample)", "Fuel dispensing unit", today - timedelta(days=500))
    issue(tn[3], "FD-N301", "Tulsi Fuels (sample)", "Fuel dispensing unit", today - timedelta(days=60))


def seed_reports_and_revocations(officers):
    """25 public reports (10 closed) and 3 revoked certificates."""
    texts = ["Display flickers and reading jumps", "Seal looks broken", "Pump seems to deliver short",
             "Certificate on the wall looks photocopied", "Weights look filed down"]
    rows = db.fetch_all("SELECT serial_number, state_code FROM certificates ORDER BY id LIMIT 25")
    for n, row in enumerate(rows):
        db.run("INSERT INTO reports (at, serial_number, description, reference, status, state_code) "
               "VALUES (:at, :s, :d, :r, :st, :state)", at=clock.stamp(), s=row.serial_number, state=row.state_code,
               d=texts[n % len(texts)] + " (sample report)", r=f"R-SEED-{n + 1:03d}",
               st="closed" if n < 10 else "open")
    for row in db.fetch_all("SELECT code FROM certificates WHERE serial_number LIKE 'EW-F21%' ORDER BY code LIMIT 3"):
        db.run("UPDATE certificates SET revoked_at = :at, revoked_by = :by, revoke_reason = :why WHERE code = :c",
               at=clock.stamp(), by="Tamil Nadu District Officer (sample)",
               why="Issued outside the officer's district (sample)", c=row.code)


def seed_walkthrough():
    """The four certificates the presentation uses, always in this order and with these codes.

    CERT-0001 VALID (the slide's QR) · CERT-0002 EXPIRED, names section 33 ·
    CERT-0003 EXPIRING SOON · CERT-0004 same serial as 0001, new owner -> fraud alert LM-201.
    These four codes are in the old guessable style on purpose so printed slides keep working.
    """
    officer = _officer("seed_demo_lab", "Priya Lab Officer (sample)", "lab_officer", "TN", "Chennai")
    today = clock.today()
    issue(officer, "WB-4471", "Sharma Weighbridge Co. (sample)", "Weighbridge", today - timedelta(days=30), code=WALKTHROUGH[0])
    issue(officer, "FD-0932", "Kaveri Fuels (sample)", "Fuel dispensing unit", today - timedelta(days=400), code=WALKTHROUGH[1])
    issue(officer, "EW-1188", "Lotus Kirana Store (sample)", "Electronic weighing instrument",
          verified_for("Electronic weighing instrument", "TN", 35), code=WALKTHROUGH[2])
    issue(officer, "WB-4471", "Nilgiri Traders (sample)", "Weighbridge", today - timedelta(days=1), code=WALKTHROUGH[3])
    seed_request()


def seed_request():
    """One waiting request from trader1, so the officer dashboard shows the trader flow."""
    trader = db.fetch_one("SELECT id, firm_name FROM users WHERE username = 'trader1'")
    if trader is None or not trader.firm_name:
        return
    if db.fetch_one("SELECT id FROM applications WHERE reference = 'A-DEMO-0001'"):
        return          # already there
    db.run("""INSERT INTO applications (reference, created_at, trader_id, firm_name, serial_number,
                  instrument_type, state_code, jurisdiction, address, note)
              VALUES ('A-DEMO-0001', :at, :t, :firm, 'FD-2210', 'Fuel dispensing unit', 'TN', 'Chennai',
                      '14 GST Road, Chennai (sample address)', 'New pump, not yet in use (sample)')""",
           at=clock.stamp(), t=trader.id, firm=trader.firm_name)


def report():
    """Counts per status band and per fraud code. Returns True if within the agreed spread."""
    today = clock.today()
    bands = {"VALID": 0, "EXPIRING SOON": 0, "EXPIRED": 0, "LONG EXPIRED": 0, "OTHER": 0}
    rows = db.fetch_all(f"SELECT {certs.COLUMNS} FROM certificates")
    for row in rows:
        result = certs.assess(row, today)
        if result["status"] == "EXPIRED" and result["days"] > 365:
            bands["LONG EXPIRED"] += 1
        else:
            bands[result["status"] if result["status"] in bands else "OTHER"] += 1
    total = len(rows) or 1
    print(f"{len(rows)} certificates")
    for band, n in bands.items():
        print(f"  {band:14} {n:4}  {100 * n / total:5.1f}%")
    alerts = dict(db.fetch_all("SELECT code, COUNT(*) FROM fraud_alerts GROUP BY code"))
    print("fraud alerts:", alerts)
    if len(rows) == 4:
        return [r.code for r in db.fetch_all("SELECT code FROM certificates ORDER BY id")] == WALKTHROUGH
    targets = {"VALID": 55, "EXPIRING SOON": 15, "EXPIRED": 20, "LONG EXPIRED": 10}
    spread_ok = all(abs(100 * bands[b] / total - pct) <= 6 for b, pct in targets.items())
    fraud_ok = all(alerts.get(code, 0) >= 2 for code in ("LM-201", "LM-202", "LM-206", "LM-207"))
    return spread_ok and fraud_ok and bands["OTHER"] == 3      # the 3 revoked ones


def main():
    """Read the flag and do that one thing."""
    flags = set(sys.argv[1:]) - {"--yes"}
    if flags not in ({"--reset"}, {"--demo"}, {"--verify"}):
        sys.exit(__doc__)
    if flags != {"--verify"}:
        wipe()
        if flags == {"--reset"}:
            seed_full()
        else:
            seed_walkthrough()
    ok = report()
    print("OK" if ok else "NOT AS EXPECTED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
