#!/usr/bin/env python3
"""Run the SENTINELX data-retention policy from the command line.

Usage:
    python scripts/retention.py --dry-run
    python scripts/retention.py --days 30
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import SessionLocal, init_db  # noqa: E402
from app.services.retention import apply_retention  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="SENTINELX data retention")
    parser.add_argument("--days", type=int, default=None, help="Override LOG_RETENTION_DAYS")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        result = apply_retention(db, days=args.days, dry_run=args.dry_run)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    finally:
        db.close()
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
