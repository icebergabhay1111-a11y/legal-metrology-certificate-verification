# Wiring auth.py into app1.py

Two separate changes. Do the first, test it, commit it. Then do the second.

## 1. Turn login on (does not touch certificate issuing yet)

In `app1.py`, right after `app = Flask(__name__)`, add:

```python
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

import auth
app.register_blueprint(auth.auth_bp)
auth.init_auth_db()
```

`secret_key` is required for Flask sessions to work at all — without it,
`session["user_id"] = ...` in auth.py will throw. Put a real random value in
the `SECRET_KEY` environment variable on Render later; the fallback here is
only for running on your own laptop.

That's it for step 1. Run the app, go to `/login`, and log in with an
account from `python seed_users.py`. You should land on `/dashboard`.

## 2. Put the officer's name on the certificate

This is the part that has to touch `app1.py`'s own code, per the task brief
("add officer_id and officer_name to the certificates table and fill them
at the moment of issue"). Three small edits, all in `app1.py`:

**a) Add the columns**, in `init_db()`, in the same migration loop that
already exists for `instrument_class` etc.:

```python
for column, ddl in [
    ("instrument_class",       "TEXT"),
    ("max_permissible_error",  "TEXT"),
    ("reverification_months",  "INTEGER"),
    ("officer_id",             "INTEGER"),      # add this line
    ("officer_name",           "TEXT"),         # add this line
]:
```

**b) Protect the submit route and capture who's issuing it.** Import the
decorator and current_user at the top of app1.py:

```python
from auth import role_required, current_user
```

Then change:

```python
@app.route("/submit", methods=["POST"])
def submit():
```

to:

```python
@app.route("/submit", methods=["POST"])
@role_required("lab_officer", "district_officer", "admin")
def submit():
    officer = current_user()
```

**c) Save and show it.** In the `INSERT INTO certificates` block, add the
two columns and two values:

```python
cursor.execute("""
    INSERT INTO certificates
    (
        serial_number, owner_name, instrument_type, verification_date,
        expiry_date, instrument_class, max_permissible_error,
        reverification_months, officer_id, officer_name
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""", (
    serial_number, owner_name, instrument_type,
    verification_date.isoformat(), expiry_date.isoformat(),
    instrument_class, max_permissible_error, months,
    officer["id"], officer["full_name"]
))
```

Then add `officer_name=officer["full_name"]` to the `render_template(
"certificate.html", ...)` call, and add one line to
`templates/certificate.html` and `templates/verify.html` to display it —
same pattern as the existing `owner_name` row. In `verify()`, add
`row[?]` for the two new columns to the SELECT and to the `certificate`
dict the same way `instrument_class` already is, so the public status
page shows who issued it too.

## Why this order

Step 1 gets logins, roles, the dashboard, the report form, and the audit
log fully working and testable — that's five of the six deliverables —
without touching anything Anikeit or anyone else has open in app1.py.
Step 2 is the one unavoidable edit to app1.py, kept as small as possible
and left for last, exactly as the task brief says: "Only when all of
that works, add officer_id and officer_name."

## Testing checklist before you push

- [ ] Log in as `trader1`, type `/dashboard` into the address bar by hand.
      You should get the 403 page, not the dashboard.
- [ ] Log in as `lab1`, `/dashboard` should work.
- [ ] Log in with a wrong password. Message should be generic
      ("Incorrect username or password"), not "wrong password" or
      "no such user".
- [ ] Do five different actions (login, failed login, logout, issue a
      certificate, submit a public report) and check `/admin/audit`
      (as `admin1`) shows all five, newest first, with correct names.
- [ ] Open `certificates.db` with a SQLite browser and confirm
      `password_hash` is a long hash string, never plain text.
- [ ] Submit `/report` with no login at all — should work and appear on
      the officer dashboard.
