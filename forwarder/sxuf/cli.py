"""Command-line interface for the SXUF forwarder."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys

from . import __version__
from .agent import ForwarderAgent
from .collectors import FileCollector, JournalCollector, WindowsEventCollector
from .config import ConfigError, load_config


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sxuf", description="SentinelX Universal Log Forwarder"
    )
    parser.add_argument("-c", "--config", default=os.environ.get("SXUF_CONFIG", "config.yaml"))
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run", help="Run continuously (default)")
    sub.add_parser("once", help="Collect, forward and exit (useful for cron / tests)")
    sub.add_parser("status", help="Print local health and buffer status")
    sub.add_parser("verify-config", help="Validate configuration without starting")
    sub.add_parser("version", help="Print the forwarder version")
    return parser


def _collectors(config):
    mapping = {
        "file": FileCollector,
        "journal": JournalCollector,
        "windows_event": WindowsEventCollector,
    }
    return [mapping[source.kind](source, config.state_path) for source in config.sources]


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    command = args.command or "run"
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if command == "version":
        print(__version__)
        return 0

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if command == "verify-config":
        print(
            json.dumps(
                {
                    "status": "ok",
                    "agent_id": config.agent_id,
                    "hostname": config.hostname,
                    "sources": [s.name for s in config.sources],
                    "config_fingerprint": config.fingerprint(),
                    "tls_verify": config.tls_verify,
                },
                indent=2,
            )
        )
        return 0

    agent = ForwarderAgent(config, _collectors(config))
    for name in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(name, agent.request_stop)
        except (ValueError, AttributeError):
            pass

    if command == "status":
        print(json.dumps(agent.status(), indent=2))
        agent.transport.close()
        agent.seen.close()
        return 0
    if command == "once":
        result = agent.once()
        print(json.dumps(result, indent=2))
        agent.shutdown()
        return 0
    agent.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
