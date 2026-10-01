"""Turn validation failures into sentences a workspace user can act on.

FastAPI and Pydantic report errors as machine-readable structures. The lab is
used by students who never see a stack trace, so every rejected request gets one
short sentence that names the field and says what to change.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_SECTIONS = {"topology": "Topology", "experiment": "Experiment"}
_COLLECTIONS = {"hosts": "Host", "switches": "Switch", "links": "Link"}
_FIELDS = {
    "after": "history position",
    "attackers": "attackers",
    "bandwidth_mbps": "bandwidth (Mb/s)",
    "baseline": "baseline seconds",
    "confirm_isolated_lab": "isolated-lab confirmation",
    "delay_ms": "delay (ms)",
    "description": "description",
    "dpid": "datapath ID (DPID)",
    "duration": "attack seconds",
    "format": "export format",
    "ip": "IPv4 address / prefix",
    "link_id": "link",
    "loss_percent": "packet loss (%)",
    "mitigation": "mitigation switch",
    "name": "name",
    "node": "device",
    "packets": "packet limit",
    "position": "canvas position",
    "protocol": "protocol",
    "rate": "rate (packets per second)",
    "recovery": "recovery seconds",
    "run_id": "run identifier",
    "source": "source device",
    "target": "target device",
    "traffic": "traffic kind",
    "token": "access token",
    "victims": "victims",
    "version": "file version",
}
_PATTERNS = {
    r"^h[a-zA-Z0-9_]{1,8}$": (
        "host names start with “h” followed by up to 8 letters, digits, or "
        "underscores, for example h1 or h2a"
    ),
    r"^s[a-zA-Z0-9_]{1,8}$": (
        "switch names start with “s” followed by up to 8 letters, digits, or "
        "underscores, for example s1 or s2a"
    ),
    r"^[a-zA-Z0-9_-]{1,40}$": (
        "use only letters, digits, hyphens, and underscores, up to 40 characters"
    ),
    "^(json|csv)$": "choose either json or csv",
}
_SKIPPED = {"body", "query", "path", "__root__"}


def _place(location: Sequence[Any]) -> str:
    parts: list[str] = []
    index = 0
    while index < len(location):
        step = location[index]
        if step in _SKIPPED:
            index += 1
            continue
        following = location[index + 1] if index + 1 < len(location) else None
        if step in _COLLECTIONS and isinstance(following, int):
            parts.append(f"{_COLLECTIONS[step]} {following + 1}")
            index += 2
            continue
        if step in _SECTIONS:
            parts.append(_SECTIONS[step])
        elif isinstance(step, int):
            parts.append(f"entry {step + 1}")
        else:
            parts.append(_FIELDS.get(str(step), str(step).replace("_", " ")))
        index += 1
    return " · ".join(parts)


def _reason(error: Mapping[str, Any]) -> str:
    kind = str(error.get("type", ""))
    context = error.get("ctx") or {}
    message = str(error.get("msg", "this value was rejected"))
    if kind == "value_error":
        return message.removeprefix("Value error, ")
    if kind == "assertion_error":
        return message.removeprefix("Assertion failed, ")
    if kind == "string_pattern_mismatch":
        pattern = str(context.get("pattern", ""))
        return _PATTERNS.get(pattern, "this value uses characters the lab cannot use")
    if kind == "extra_forbidden":
        return "this lab has no such setting, so remove it and try again"
    if kind == "missing":
        return "this value is required"
    if kind in {"greater_than_equal", "greater_than"}:
        limit = context.get("ge", context.get("gt"))
        word = "at least" if kind == "greater_than_equal" else "greater than"
        return f"use a value {word} {limit}"
    if kind in {"less_than_equal", "less_than"}:
        limit = context.get("le", context.get("lt"))
        word = "at most" if kind == "less_than_equal" else "less than"
        return f"use a value {word} {limit}"
    if kind in {"too_short", "min_length", "string_too_short"}:
        return f"at least {context.get('min_length', 1)} is required here"
    if kind in {"too_long", "max_length", "string_too_long"}:
        return f"at most {context.get('max_length')} is allowed here"
    if kind in {"int_parsing", "int_type", "int_from_float"}:
        return "use a whole number"
    if kind in {"float_parsing", "float_type", "decimal_parsing"}:
        return "use a number"
    if kind in {"bool_parsing", "bool_type"}:
        return "use yes or no"
    if kind == "uuid_parsing":
        return "this is not a valid identifier"
    if kind == "json_invalid":
        return "this is not valid JSON"
    if kind == "literal_error":
        allowed = context.get("expected")
        return f"choose one of {allowed}" if allowed else message
    return message[0].lower() + message[1:] if message else message


def describe(errors: Sequence[Mapping[str, Any]], limit: int = 3) -> str:
    """Return one short, actionable sentence per rejected field."""

    sentences: list[str] = []
    for error in errors[:limit]:
        place = _place(error.get("loc") or ())
        reason = _reason(error)
        sentences.append(f"{place}: {reason}." if place else f"{reason}.")
    if not sentences:
        return "The values sent to the lab were rejected."
    if (rest := len(errors) - limit) > 0:
        sentences.append(f"{rest} further problem{'s' if rest > 1 else ''} not listed.")
    return " ".join(sentences)


def describe_exception(error: BaseException) -> str:
    """Return a readable reason for an exception raised while parsing a file."""

    if isinstance(error, KeyError):
        return f"a required field ({error.args[0]}) is missing"
    if isinstance(error, (ValueError, TypeError)):
        text = str(error).strip()
        return text or "a value has the wrong type"
    return "the file could not be read"
