"""A deliberately small, documented subset of the Sigma rule language.

Supported fields are the keys of a normalised event (action, event_code,
username, source_ip, host, message, ...). Supported modifiers: ``contains``,
``startswith``, ``endswith``. Supported conditions: ``selection``,
``selection and selection2``, and ``selection | count() > N [by field]`` with a
``timeframe`` such as ``5m``. Anything else is rejected with a clear error
rather than silently ignored, so operators know exactly what is enforced.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import yaml

from ..utils.timeutil import to_utc_naive
from .types import DetectionEvent


@dataclass
class SigmaSelection:
    name: str
    patterns: dict[str, Any]


@dataclass
class SigmaRule:
    title: str
    rule_id: str
    level: str
    description: str
    tags: list[str] = field(default_factory=list)
    selections: dict[str, SigmaSelection] = field(default_factory=dict)
    condition: str = "selection"
    count_threshold: int | None = None
    count_operator: str = ">"
    group_by: str | None = None
    timeframe: timedelta = field(default_factory=lambda: timedelta(minutes=5))


def _parse_timeframe(value: str) -> timedelta:
    match = re.fullmatch(r"(\d+)\s*([smhd])", value.strip().lower())
    if not match:
        return timedelta(minutes=5)
    amount, unit = int(match.group(1)), match.group(2)
    return timedelta(**{"seconds" if unit == "s" else "minutes" if unit == "m" else "hours" if unit == "h" else "days": amount})


def parse_sigma_rule(yaml_text: str) -> SigmaRule:
    doc = yaml.safe_load(yaml_text)
    if not isinstance(doc, dict) or "detection" not in doc:
        raise ValueError("Sigma rule must be a mapping containing 'detection'")
    detection = doc["detection"]
    selections: dict[str, SigmaSelection] = {}
    for name, definition in detection.items():
        if name == "condition" or not isinstance(definition, dict):
            continue
        selections[name] = SigmaSelection(name=name, patterns=definition)
    condition = str(detection.get("condition", "selection"))
    threshold = None
    operator = ">"
    group_by = None
    if "|" in condition:
        base, aggregation = (part.strip() for part in condition.split("|", 1))
        condition = base
        count_match = re.search(r"count\(\)\s*(>=|>|<=|<|=)\s*(\d+)", aggregation)
        if count_match:
            operator, threshold = count_match.group(1), int(count_match.group(2))
        by_match = re.search(r"\bby\s+(\w+)", aggregation)
        if by_match:
            group_by = by_match.group(1)
    if condition not in selections and not all(part.strip() in selections for part in condition.split("and")):
        raise ValueError(f"Unsupported Sigma condition: {condition!r}")
    return SigmaRule(
        title=str(doc.get("title", "Unnamed Sigma rule")),
        rule_id=str(doc.get("id", "")),
        level=str(doc.get("level", "medium")).upper(),
        description=str(doc.get("description", "")),
        tags=list(doc.get("tags", []) or []),
        selections=selections,
        condition=condition,
        count_threshold=threshold,
        count_operator=operator,
        group_by=group_by,
        timeframe=_parse_timeframe(str(detection.get("timeframe", doc.get("timeframe", "5m")))),
    )


def _match_pattern(actual: Any, pattern: Any) -> bool:
    actual_str = "" if actual is None else str(actual)
    if isinstance(pattern, list):
        return any(_match_pattern(actual_str, item) for item in pattern)
    text = str(pattern)
    modifier = None
    if "|" in text:
        text, modifier = text.rsplit("|", 1)
    if modifier == "contains":
        return text.lower() in actual_str.lower()
    if modifier == "startswith":
        return actual_str.lower().startswith(text.lower())
    if modifier == "endswith":
        return actual_str.lower().endswith(text.lower())
    if text == "null" or text == "":
        return actual is None or actual_str == ""
    return actual_str.lower() == text.lower()


def selection_matches(selection: SigmaSelection, event: DetectionEvent) -> bool:
    data = dict(event.payload)
    for field_name in (
        "event_code", "action", "username", "source_ip",
        "destination_ip", "host", "message", "event_uid",
    ):
        data.setdefault(field_name, getattr(event, field_name, None))
    for field_name, pattern in selection.patterns.items():
        actual = data.get(field_name)
        if not _match_pattern(actual, pattern):
            return False
    return True


def evaluate_sigma_rule(rule: SigmaRule, events: list[DetectionEvent]) -> list[dict[str, Any]]:
    """Return matches as dictionaries: {events, group_value, evidence}."""
    required = [part.strip() for part in rule.condition.split("and")]
    matching = [
        event
        for event in events
        if all(selection_matches(rule.selections[name], event) for name in required)
    ]
    if rule.count_threshold is None:
        return [{"events": matching, "group_value": None, "evidence": {"matched": len(matching)}}] if matching else []

    groups: dict[Any, list[DetectionEvent]] = {}
    for event in matching:
        key = event.payload.get(rule.group_by) if rule.group_by else "__all__"
        groups.setdefault(str(key), []).append(event)
    results: list[dict[str, Any]] = []
    for key, group in groups.items():
        ordered = sorted(group, key=lambda e: e.timestamp)
        # Sliding window: keep only events inside the rule timeframe.
        window_events: list[DetectionEvent] = []
        for event in ordered:
            window_events = [e for e in window_events if event.timestamp - e.timestamp <= rule.timeframe]
            window_events.append(event)
            count = len(window_events)
            if (
                (rule.count_operator == ">" and count > rule.count_threshold)
                or (rule.count_operator == ">=" and count >= rule.count_threshold)
                or (rule.count_operator == "<" and count < rule.count_threshold)
                or (rule.count_operator == "<=" and count <= rule.count_threshold)
                or (rule.count_operator == "=" and count == rule.count_threshold)
            ):
                results.append(
                    {
                        "events": window_events,
                        "group_value": key,
                        "evidence": {
                            "count": count,
                            "threshold": rule.count_threshold,
                            "timeframe_seconds": int(rule.timeframe.total_seconds()),
                            "group_by": rule.group_by,
                        },
                    }
                )
                break
    return results
