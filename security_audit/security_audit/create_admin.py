"""Secure interactive first administrator setup."""
import getpass
import re

from .api import create_admin
from .db import connect


def main():
    db = connect()
    try:
        if db.execute("SELECT count(*) FROM users").fetchone()[0]:
            raise SystemExit("An account already exists; first-admin setup is disabled.")
        full_name = input("Full name: ").strip()
        username = input("Username: ").strip().lower()
        email = input("Admin email: ").strip().lower()
        password = getpass.getpass("Admin password (6+ characters): ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            raise SystemExit("Passwords do not match.")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,39}", username):
            raise SystemExit("Username must be 3–40 letters, numbers, dots, underscores, or hyphens.")
        if not create_admin(db, email, password, full_name, username):
            raise SystemExit("An account already exists; no administrator was changed.")
        print("Administrator created.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
