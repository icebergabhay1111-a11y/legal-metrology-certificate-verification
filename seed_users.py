"""
seed_users.py — create one test account per role.

Run once, from the project folder, after auth.py is wired into app1.py:

    python seed_users.py

Prints the plaintext passwords to your own terminal only, once.
Put them in the team group chat, not in GitHub. The database
never stores plain text — only the hash goes in.

Safe to run again later: existing usernames are skipped, not
overwritten.
"""

import secrets
import sqlite3

from werkzeug.security import generate_password_hash

import auth

DATABASE = "certificates.db"

# username, full name, role, state code, jurisdiction
USERS = [
    ("trader1",    "Ramesh Trader",           "trader",           "TN", "Chennai"),
    ("lab1",       "Priya Lab Officer",       "lab_officer",      "TN", "Chennai"),
    ("district1",  "Suresh District Officer", "district_officer", "TN", "Chennai District"),
    ("admin1",     "Admin User",              "admin",            "TN", "State HQ"),
]


def main():
    auth.init_auth_db()

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print()
    print("Seeded accounts — share these in the team chat, not GitHub:")
    print()

    for username, full_name, role, state_code, jurisdiction in USERS:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            print(f"  {username:12} already exists, skipped")
            continue

        password = secrets.token_urlsafe(6)
        password_hash = generate_password_hash(password)

        cursor.execute(
            """INSERT INTO users
               (username, password_hash, full_name, role, state_code, jurisdiction)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (username, password_hash, full_name, role, state_code, jurisdiction),
        )

        print(f"  {username:12} / {password:12} ({role})")

    conn.commit()
    conn.close()
    print()


if __name__ == "__main__":
    main()
