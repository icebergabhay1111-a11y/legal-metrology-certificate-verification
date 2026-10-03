# Sahi Daam — Legal Metrology certificate verification (student prototype)

Smart India Hackathon 2026 · problem statement SIH26036, *Online Verification System for Weighing
and Measuring Instruments* (Department of Consumer Affairs) · Team VITV SahiDaam, VIT.

**This is a student prototype. It is not operated by, or affiliated with, any Government department,
and a record here is not a legal certificate.**

## What it does

| | |
|---|---|
| **Status on the day you check** | Scanning a certificate's QR, or typing its ID or the instrument's serial number, shows VALID, EXPIRING SOON, EXPIRED, REVOKED, NOT VERIFIED or NOT FOUND, worked out that day. |
| **Expiry is calculated, never typed** | The instrument type and the State's rules set the period; there is no expiry field. |
| **Signed records** | Each certificate is signed with Ed25519 at issue. If a stored field is edited later, the page says NOT VERIFIED. Keys carry an id, so rotating the key keeps old certificates verifiable. |
| **Offline checking** | The QR also carries the signed fields. The offline checker (`/offline`, installable on a phone) verifies the signature with no network, and says plainly that revocation cannot be checked offline. |
| **Revocation** | District officers and admins can revoke a certificate with a reason; it then reads REVOKED. |
| **Traders** | A trader sees every certificate in their firm's name with today's status, prints them, and requests a verification visit. The request reaches the officers of that State, who verify and issue from it (the form is filled in) or decline with a reason the trader sees. |
| **One State per officer** | Officers see and act on their own State only: issuing, revoking, due lists, requests and public reports. The admin sees every State. Eight States are configured (Tamil Nadu, Delhi, Mizoram, Maharashtra, Karnataka, Gujarat, Uttar Pradesh, Kerala). |
| **Four fraud checks at issue** | Same serial with a different owner (LM-201), officer outside their district (LM-202), more certificates in a day than the State allows (LM-206), a lapsed instrument moved to a new owner without re-verification (LM-207). A check raises an alert; it does not block. |
| **Per-State rules** | Periods, districts, reminder window and daily limit live in `states/XX.json`. A new State is a new file. Fee figures in those files are placeholders and say so. |
| **Accountability** | Four roles, a named officer on every certificate, and a hash-chained audit log that shows if a past entry was edited or deleted. |
| **Stable error codes** | Every result and error has a code (`LM-` for the domain, `SYS-` for the software) and every response a request id. See `errors.py`. |

What it does **not** do yet: send reminders by SMS or email, collect fees,
or use a Digital Signature Certificate under the IT Act. The interface is English only.

## Run it

```
python -m pip install -r requirements.txt pytest
python -m pytest -q                 # every test should pass
python seed_demo.py --demo          # the four walkthrough certificates (CERT-0001 to 0004)
python app1.py                      # http://127.0.0.1:5050
```

Local demo logins (`lab1`, `district1`, `admin1`, `trader1`, `mz1`, and the team officers `anikeit`, `abhay`, `anvita`, `krishna`, `shreyash`, `vaibhavi`) use the password `sahidaam2026`.
That password is refused when `APP_ENV=production`; the live site uses its own passwords.

`python seed_demo.py --reset` generates about 900 certificates spread across every status, with fraud
cases and near misses. All names end in "(sample)".

## Files

| File | What it holds |
|---|---|
| `app1.py` | Start-up, public pages, officer pages, issuing |
| `auth.py` | Login, roles, audit log, dashboard, public reports |
| `applications.py` | The trader's page and verification requests |
| `certs.py` | Certificate codes, status rules, lookups |
| `signing.py` | Ed25519 signing with key ids; `retired_keys.json` holds old public keys |
| `fraud.py` | The four fraud rules, as pure functions |
| `errors.py` | Every `LM-`/`SYS-` code and the error page |
| `security.py` | CSRF, security headers, rate limits, request ids |
| `config.py` | Reads `states/*.json`, `enforcement.json`, `contacts_national.json` |
| `db.py` + `migrations/` | SQLite locally, PostgreSQL when `DATABASE_URL` is set; Alembic migrations |
| `clock.py` | India's date and time (the server runs on UTC) |
| `seed_demo.py` | Test data |

Deployment settings are in `DEPLOY.md`.

## Evidence notes

- Re-verification periods follow rule 27(2) of the Legal Metrology (General) Rules, 2011, as reported by
  secondary sources. The gazette text has not been read; the periods are configuration and every
  status page says they are unverified.
- Penalties shown on expired certificates come from `enforcement.json`, with the page of the
  Legal Metrology Act, 2009 they were taken from.
- Every phone number and address shown carries its source and the date it was checked.
