"""Startup entry point for SENTINELX.

Usage:
    python run.py
    HOST=0.0.0.0 PORT=8000 python run.py
"""

from __future__ import annotations

import os

import uvicorn

from app.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=settings.debug and os.getenv("RELOAD", "1") == "1",
        log_level="info",
    )
