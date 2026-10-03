# DEPLOY.md — running Sahi Daam on Render with a Neon database

Team VITV SahiDaam · SIH26036 · updated 2 October 2026

## 1. What runs where

| Part | Service | Free-plan facts that matter (checked 24 Sep 2026) |
|---|---|---|
| The app | Render web service, `gunicorn app1:app` | 750 instance hours a month; sleeps after 15 minutes with no traffic and takes about a minute to wake; the disk is wiped on every deploy (render.com/docs/free) |
| The database | Neon PostgreSQL | 0.5 GB per project; 100 CU-hours a month (about 400 hours at the smallest size); sleeps after 5 idle minutes and that cannot be turned off (neon.com/docs/introduction/plans) |
| Keep-awake ping | Any free uptime monitor | Must call `/healthz`, which never touches the database (see section 4) |

Netlify cannot host this app (its functions are JavaScript/TypeScript only, and it does not run a
long-lived Python server). Render's own free Postgres expires after 30 days, so it is not used.

Run **one** gunicorn worker (the default). The rate limiter keeps its counters in memory; with several
workers each would count separately.

## 2. Environment variables on Render

| Name | Value | Why |
|---|---|---|
| `BASE_URL` | `https://legal-metrology-certificate-verification.onrender.com` | The QR code points here. Without it the QR points at a private address |
| `SECRET_KEY` | long random string | Signs the login cookie. Required when `APP_ENV=production` |
| `SIGNING_KEY` | output of `python signing.py --print-key` | Signs certificates. Required when `APP_ENV=production`: the app refuses to start without it (SYS-502) |
| `PW_TRADER`, `PW_LAB`, `PW_DISTRICT`, `PW_ADMIN`, `PW_MZ` | one password each | In production an account whose variable is missing is not created |
| `TEAM_PASSWORD` | one password | Shared by the six team demo officers (anikeit, abhay, anvita, krishna, shreyash, vaibhavi), one per State. Not set = those accounts are not created |
| `DATABASE_URL` | Neon connection string | Records survive deploys. Tables are created and upgraded automatically at start-up |
| `APP_ENV` | `production` | Turns on the production checks and the `Secure` cookie flag |

Generate a random value on your own computer with
`python -c "import secrets; print(secrets.token_urlsafe(32))"`. Never paste a secret into GitHub,
the slides or a group chat.

## 3. Connecting Neon (about 10 minutes)

1. Create a project at console.neon.tech. Pick the region closest to the Render service's region.
2. Copy the connection string (it starts `postgresql://` and ends with `sslmode=require`).
3. Render → the service → Environment → add `DATABASE_URL`. Save, rebuild and deploy.
4. When it is Live: open `/admin/health` as `admin1`. "database" should say `postgresql` and
   "migration" should say `0005`.
5. Issue one certificate, redeploy, and open its status page again. If it is still there, the data is durable.

The `postgres://` vs `postgresql://` prefix difference is handled in `db.py`.

For a separate **test database** (screenshots, rehearsals), create a second Neon project and run the
seeder against it from your own computer:

```
set DATABASE_URL=<test database string>        (Windows)
python seed_demo.py --reset --yes              (about 900 certificates)
python seed_demo.py --demo --yes               (only the four walkthrough certificates)
```

The seeder refuses to run when `APP_ENV=production`, and asks for `--yes` before touching any hosted
database. Never run it against the database the judges see unless you mean to replace its data.

## 4. Keeping it awake without exhausting the database

Point the uptime monitor at `https://<site>/healthz` every 5 minutes. `/healthz` answers `ok` without
touching the database, so Neon still goes to sleep between real visits. A monitor that loaded a
status page instead would keep Neon awake about 720 hours a month, above the free allowance, and the
database would stop mid-month. (Arithmetic from the figures above.)

Even so: **open the site a few minutes before any demonstration.**

## 5. Rotating the signing key

1. Run `python signing.py` locally with the current key set to print its key id and public key
   (or copy them from `/keys.json` on the live site).
2. Add `{"public_key": "<old public key>"}` to `retired_keys.json` and commit it. Public keys are safe
   to publish.
3. Set the new `SIGNING_KEY` on Render and deploy.

Certificates signed with the old key keep reading VERIFIED; new ones use the new key. Each
certificate stores the id of the key that signed it.

## 6. After a deploy — a two-minute check

- `/healthz` says `ok`.
- `/admin/health` shows every check green.
- Log in as `lab1`; issue a certificate; scan its QR with a phone; it reads VALID.
- `/offline` says "Ready" on a phone; with the phone in airplane mode it still checks that QR.
