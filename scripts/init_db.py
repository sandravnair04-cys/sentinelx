"""Initialize the database and seed safe demo data.

Usage:
    python scripts/init_db.py            # seed demo data (default from .env)
    python scripts/init_db.py --no-demo  # create schema + users + rules only
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import SessionLocal, init_db  # noqa: E402
from app.services.seed import seed_database  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-demo", action="store_true", help="Do not seed simulated events/incidents")
    args = parser.parse_args()
    init_db()
    db = SessionLocal()
    try:
        result = seed_database(db, demo=not args.no_demo)
    finally:
        db.close()
    print("Database initialised:")
    for key, value in result.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
