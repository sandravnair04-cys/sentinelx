"""Reset and re-seed the demo dataset (destructive to demo rows only).

Usage:
    python scripts/seed.py            # layers demo data onto the current DB
    python scripts/seed.py --reset    # drops all tables first (lab use only)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import Base, SessionLocal, engine, init_db  # noqa: E402
from app.services.seed import seed_database  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="DROP all tables before seeding (irreversible)")
    args = parser.parse_args()
    if args.reset:
        confirm = input("This deletes all SENTINELX data. Type 'yes' to continue: ")
        if confirm.strip().lower() != "yes":
            print("Aborted.")
            return
        Base.metadata.drop_all(bind=engine)
    init_db()
    db = SessionLocal()
    try:
        result = seed_database(db, demo=True)
    finally:
        db.close()
    print("Seed complete:", result)


if __name__ == "__main__":
    main()
