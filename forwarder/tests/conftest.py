"""Make the standalone forwarder package importable in tests."""

import sys
from pathlib import Path

FORWARDER_DIR = Path(__file__).resolve().parents[1]
if str(FORWARDER_DIR) not in sys.path:
    sys.path.insert(0, str(FORWARDER_DIR))
