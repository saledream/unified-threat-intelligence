import getpass
import sys

from sqlalchemy import select

from app.auth.security import hash_password
from app.database import SessionLocal
from app.models import User


def main():
    db = SessionLocal()
    try:
        existing_admin = db.scalar(
            select(User.id).where(User.role == "admin")
        )

        if existing_admin is not None:
            print("An administrator already exists. Bootstrap refused.")
            return 1

        username = input("Administrator username: ").strip()
        if len(username) < 3 or len(username) > 80:
            print("Username must contain 3 to 80 characters.")
            return 1

        password = getpass.getpass("Administrator password: ")
        confirmation = getpass.getpass("Confirm password: ")

        if password != confirmation:
            print("Passwords do not match.")
            return 1

        if len(password) < 12:
            print("Password must contain at least 12 characters.")
            return 1

        if db.scalar(select(User.id).where(User.username == username)):
            print("That username already exists.")
            return 1

        admin = User(
            username=username,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        )

        db.add(admin)
        db.commit()
        print(f"Administrator account '{username}' created successfully.")
        return 0

    except Exception:
        db.rollback()
        print("Administrator bootstrap failed. Check the database connection.")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
