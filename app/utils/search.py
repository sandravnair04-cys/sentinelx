"""Small, safe search-query parser for the Log Explorer.

Syntax (implicit AND, case-insensitive):
  failed login                 both terms must appear anywhere
  "failed password"            exact phrase
  user:administrator           structured field
  host:WIN-01 ip:203.0.113.77  multiple fields
  -status:success              negation
  severity:high                value from normalised_event.severity

Supported field aliases: host/hostname, ip/source_ip/src, user/username,
severity, type/event_type, source, code/event_code, action, agent/agent_id,
event/event_id. All values are returned as literal strings and applied through
SQLAlchemy parameters, never interpolated into SQL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_TOKEN = re.compile(r'(-?)([a-zA-Z_]+):("[^"]+"|\S+)|(-?)("[^"]+"|\S+)')

_FIELD_ALIASES = {
    "host": "host", "hostname": "host",
    "ip": "source_ip", "src": "source_ip", "source_ip": "source_ip",
    "user": "username", "username": "username",
    "severity": "severity", "level": "severity",
    "type": "event_type", "event_type": "event_type",
    "source": "source", "code": "event_code", "event_code": "event_code",
    "action": "action", "agent": "agent_id", "agent_id": "agent_id",
    "event": "event_id", "event_id": "event_id",
}


@dataclass
class Term:
    field: str | None
    value: str
    negated: bool = False


@dataclass
class ParsedQuery:
    terms: list[Term] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors


def _clean(value: str) -> str:
    return value[1:-1] if len(value) >= 2 and value.startswith('"') else value


def parse_query(text: str) -> ParsedQuery:
    result = ParsedQuery()
    for match in _TOKEN.finditer(text or ""):
        field_prefix, field_name, field_value, free_neg, free_value = match.groups()
        if field_name:
            key = _FIELD_ALIASES.get(field_name.lower())
            if key is None:
                result.errors.append(f"Unknown field: {field_name}")
                continue
            result.terms.append(Term(field=key, value=_clean(field_value), negated=bool(field_prefix)))
        else:
            value = _clean(free_value)
            if value:
                result.terms.append(Term(field=None, value=value, negated=bool(free_neg)))
    return result
