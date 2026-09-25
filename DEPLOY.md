# DEPLOY.md — hosting, and why login kept failing

Team SahiDaam · SIH26036 · written 9 September 2026

---

## 1. The bug Vaibhavi hit — it was not what we thought

We believed *"the free Render plan doesn't allow passwords."* That is not true.
Render runs Flask sessions and hashed passwords perfectly well on the free plan.

The real cause is one line in Render's own docs:

> "any changes to your web service's filesystem (uploaded images, local SQLite
> databases, etc.) are **lost** every time the service redeploys, restarts, or
> spins down."
> — <https://render.com/docs/free>, read 9 September 2026

Our users live in `certificates.db`. That file is gitignored, so it is created
fresh and **empty** on every boot. `seed_users.py` was meant to fill it, but the
free plan gives you no shell to run it in. So the live site had **zero users**,
and nobody could log in. Nothing to do w/ passwords being banned.

Two more free-plan facts from the same page, both matter tomorrow:

> "Render **spins down** a Free web service that goes 15 minutes without
> receiving any inbound traffic." … "This process takes about one minute."

> "**Free Render Postgres databases expire 30 days after creation.**"

**Open the site ~5 minutes before the review and keep the tab open**, or the
first judge to scan the QR waits a minute staring at a blank page.

---

## 2. What we changed to fix it

`auth.py` now has `ensure_demo_users()`, called on every startup from `app1.py`.
It creates the demo accounts if they are missing, and skips them if they exist,
i.e. it is safe to run a thousand times. So however often Render wipes the disk,
the logins come back by themselves.

| Username | Password | Role | State |
|---|---|---|---|
| `trader1` | `sahidaam2026` | trader | TN |
| `lab1` | `sahidaam2026` | lab officer | TN |
| `district1` | `sahidaam2026` | district officer | TN |
| `admin1` | `sahidaam2026` | admin | TN |
| `mz1` | `sahidaam2026` | lab officer | **MZ** (for the two-State demo) |

Set env vars `PW_TRADER`, `PW_LAB`, `PW_DISTRICT`, `PW_ADMIN`, `PW_MZ` on Render
to use real passwords instead. No code change needed.

**Certificates still vanish on redeploy.** That is fine for a demo — just
re-create the demo certificates after your last deploy. Section 4 fixes it
properly, but *not tonight*.

---

## 3. Netlify vs Render — the team asked, so here is the answer

**Netlify cannot host this app.** Not "is worse at" — cannot.

Netlify's own function API reference says:

> "Use this API reference to write serverless function files with **JavaScript or
> TypeScript**."
> — <https://docs.netlify.com/build/functions/api/>, read 9 September 2026

**Python is not a supported language for Netlify Functions.** And Netlify runs
short-lived serverless functions, not a long-running `gunicorn app1:app` process.
Moving to Netlify means rewriting the entire application in JavaScript. Netlify
*does* now offer a managed Postgres, but a database is no use if the app cannot run.

| | Render (free) | Netlify (free) |
|---|---|---|
| Runs Python / Flask | **Yes** | **No** — JS/TS functions only |
| Long-running server (gunicorn) | Yes | No — serverless functions |
| Server-side sessions + password login | Yes | Only if rewritten in JS |
| Managed database | Postgres, **expires after 30 days** | Managed Postgres |
| File storage survives restart | **No** — ephemeral | No |
| Sleeps when idle | Yes, after 15 min; ~1 min to wake | Functions are on demand |
| Work to migrate our app | none, we are on it | rewrite everything |

**Verdict: stay on Render.** Tell the team plainly — Netlify is a good product
for static sites and JavaScript, and the wrong tool for a Python server.

---

## 4. If we want the data to survive — do this AFTER the review

The cleanest free fix is to keep Render for the app and put the database on
**Neon**, a free hosted Postgres. Their plans page, read 9 September 2026
(<https://neon.com/docs/introduction/plans>):

- **0.5 GB storage per project**, up to 100 projects, **$0/month**
- 100 CU-hours per project per month
- Compute **scales to zero after 5 minutes idle** and that "cannot be disabled"
  on the free plan — so the first query after a quiet spell is slow, the same
  trade-off Render already has
- Unlike Render's own free Postgres, **it does not expire after 30 days**

Migration sketch (about two hours, **do not attempt it the night before**):

1. Make a Neon project, copy the connection string.
2. On Render add env var `DATABASE_URL` = that string.
3. `pip install psycopg[binary]` and add it to `requirements.txt`.
4. Replace `sqlite3.connect(DATABASE)` with a small helper that uses Postgres
   when `DATABASE_URL` is set and SQLite when it is not, so local dev keeps working.
5. Change `AUTOINCREMENT` to `SERIAL`, and `?` placeholders to `%s`.

**Known trap:** some providers hand you a URL beginning `postgres://`, which
SQLAlchemy no longer accepts. Fix it in one line before connecting:

```python
url = os.environ["DATABASE_URL"].replace("postgres://", "postgresql://", 1)
```

### What we rejected, and why

- **PythonAnywhere free** — their pricing page, read 9 September 2026, lists the
  free Beginner account as 1 web app, 512 MB storage, 100 CPU-seconds a day, and
  **no MySQL or PostgreSQL access included**. Lots of older advice online says the
  free tier gives you MySQL. Going by the page today, it does not. So it does not
  solve our problem.
- **Render's own free Postgres** — expires 30 days after creation. Fine for a
  demo, wrong for anything we would say is production.
- **Supabase, Railway, Fly.io** — not checked in time. If anyone asks, say we
  compared Render, Netlify, Neon and PythonAnywhere and have not evaluated the
  others. Do not guess at their terms.

---

## 5. Env vars to set on Render

| Name | Value | Why |
|---|---|---|
| `BASE_URL` | `https://legal-metrology-certificate-verification.onrender.com` | Without it the QR points at a private IP and no phone can open it |
| `SECRET_KEY` | any long random string | Signs the login session cookie. The default is `dev-secret-change-me` — change it |
| `SIGNING_KEY` | output of `python signing.py --print-key` | Keeps certificate signatures valid across redeploys. Without it a new key is made each boot and old certificates read "NOT VERIFIED" |
| `PW_TRADER`, `PW_LAB`, `PW_DISTRICT`, `PW_ADMIN`, `PW_MZ` | one strong password each | In production an account whose variable is missing is **not created**. The demo password in the source works only locally |
| `DATABASE_URL` | Neon connection string (starts `postgresql://`) | Records survive redeploys. Without it the app uses a local SQLite file, which Render erases on every deploy. Tables are created automatically on start by the migrations in `migrations/` |
| `APP_ENV` | `production` | Set this **last**. Turns on the two safety checks: no start without `SECRET_KEY`, no account without its own password |

Start command stays `gunicorn app1:app`.
