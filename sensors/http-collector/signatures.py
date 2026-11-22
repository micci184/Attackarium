"""Extensible, non-executing HTTP signature detection for candidate CVE probes.

Security and design invariants:
- Strictly bounded inspection lengths and decode/deobfuscation passes (no ReDoS).
- Never executes payloads, never resolves DNS/JNDI, and never fetches attacker URLs.
- Detection records contain ONLY structured metadata (no raw payloads, no attacker
  URLs, no credentials, no raw header values).
- Every match is framed as a suspected attack attempt / candidate hypothesis,
  never confirmed exploitation.
- Adding a new CVE rule requires adding one SignatureRule entry to SIGNATURE_RULES
  without modifying the HTTP collector core.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Iterable

# Explicit inspection caps.
MAX_INSPECT_PATH_BYTES = 2048
MAX_INSPECT_HEADER_VALUE_BYTES = 2048
MAX_INSPECT_HEADERS = 64
MAX_INSPECT_BODY_BYTES = 4096
MAX_URL_DECODE_PASSES = 2
MAX_OBFUSCATION_PASSES = 4
MAX_DETECTIONS_PER_EVENT = 10

CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
SENSITIVE_NAME_RE = re.compile(
    r"(pass(word|wd|phrase)?|pwd|secret|token|auth(orization)?|cookie|session|api[_-]?key|private[_-]?key|cred(ential)?s?|jwt|bearer|access[_-]?key)",
    re.IGNORECASE,
)
SAFE_HEADER_NAME_RE = re.compile(r"^[a-z0-9-]{1,48}$")

# Linear-time, bounded Log4j obfuscation wrappers (no nested quantifiers).
_UNICODE_ASCII_ESCAPE_RE = re.compile(r"\\u00([2-7][0-9a-fA-F])")
_LOG4J_CASE_LOOKUP_RE = re.compile(r"\$\{(?:lower|upper):([^${}]{1,32})\}", re.IGNORECASE)
_LOG4J_DEFAULT_LOOKUP_RE = re.compile(r"\$\{[^${}]{0,64}:-([^${}]{1,32})\}")
_LOG4J_DATE_LOOKUP_RE = re.compile(r"\$\{date:'([^'${}]{1,16})'\}", re.IGNORECASE)

# Linear-time JNDI lookup patterns applied after normalization + lowercasing.
_JNDI_WITH_SCHEME_RE = re.compile(
    r"\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|corba|nds|http|https)\s*:"
)
_JNDI_GENERIC_RE = re.compile(r"\$\{\s*jndi\s*:")

# Used to strip attacker-controlled JNDI expressions/URLs from stored paths/headers.
_JNDI_EXPRESSION_RE = re.compile(r"\$\{[^\r\n]{0,512}\}")
_JNDI_PROTOCOL_URI_RE = re.compile(
    r"(?:ldap|ldaps|rmi|iiop|corba|nds)://[^\s'\"}\])<>,;]+",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class InspectionInput:
    method: str
    raw_path: str
    headers: tuple[tuple[str, str], ...]
    body_bytes: bytes
    body_truncated: bool = False
    max_body_bytes: int = MAX_INSPECT_BODY_BYTES


@dataclass(frozen=True)
class SignatureMatch:
    signature_id: str
    rule_version: str
    candidate_cve: str
    matched_location: str
    confidence: float
    classification: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "rule_version": self.rule_version,
            "candidate_cve": self.candidate_cve,
            "matched_location": self.matched_location,
            "confidence": self.confidence,
            "classification": self.classification,
            "summary": self.summary,
        }


@dataclass(frozen=True)
class SignatureRule:
    signature_id: str
    rule_version: str
    candidate_cve: str
    classification: str
    match_text: Callable[[str], tuple[float, str] | None]


def safe_header_location(header_name: str) -> str:
    """Return a sanitized location label without leaking sensitive header names."""
    cleaned = CONTROL_CHARS_RE.sub("", header_name).strip().lower()
    if not cleaned or SENSITIVE_NAME_RE.search(cleaned):
        return "header:redacted"
    if not SAFE_HEADER_NAME_RE.match(cleaned):
        return "header:other"
    return f"header:{cleaned}"


def _decode_unicode_ascii_escapes(text: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        codepoint = int(match.group(1), 16)
        return chr(codepoint) if 0x20 <= codepoint <= 0x7E else match.group(0)

    return _UNICODE_ASCII_ESCAPE_RE.sub(_replace, text)


def normalize_for_inspection(raw: str, max_chars: int) -> str:
    """Bounded URL-decoding and Log4j lookup simplification for signature matching."""
    text = CONTROL_CHARS_RE.sub("", raw[:max_chars])
    for _ in range(MAX_URL_DECODE_PASSES):
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            break
        text = CONTROL_CHARS_RE.sub("", decoded[:max_chars])

    text = _decode_unicode_ascii_escapes(text)

    for _ in range(MAX_OBFUSCATION_PASSES):
        reduced = _LOG4J_CASE_LOOKUP_RE.sub(r"\1", text)
        reduced = _LOG4J_DEFAULT_LOOKUP_RE.sub(r"\1", reduced)
        reduced = _LOG4J_DATE_LOOKUP_RE.sub(r"\1", reduced)
        if reduced == text:
            break
        text = reduced[:max_chars]

    return text.lower()


def redact_jndi_references(value: str) -> str:
    """Strip attacker JNDI expressions and callback URIs before storing metadata."""
    normalized_check = normalize_for_inspection(value, max_chars=MAX_INSPECT_HEADER_VALUE_BYTES)
    has_jndi = _JNDI_GENERIC_RE.search(normalized_check) is not None
    has_jndi_uri = _JNDI_PROTOCOL_URI_RE.search(normalized_check) is not None
    if not has_jndi and not has_jndi_uri:
        return value

    redacted = _JNDI_PROTOCOL_URI_RE.sub("[REDACTED_JNDI_URI]", value)
    if has_jndi:
        replaced = _JNDI_EXPRESSION_RE.sub("[REDACTED_JNDI]", redacted)
        # If encoding or escaping hid literal ${...}, redact the whole value so
        # attacker callback URLs cannot leak in encoded form.
        if replaced == redacted:
            return "[REDACTED_JNDI]"
        redacted = replaced
    elif redacted == value:
        return "[REDACTED_JNDI_URI]"
    return redacted


def _match_log4shell(normalized_lower: str) -> tuple[float, str] | None:
    if _JNDI_WITH_SCHEME_RE.search(normalized_lower):
        return (
            0.9,
            "Suspected CVE-2021-44228 (Log4Shell) JNDI lookup probe; candidate hypothesis only, not confirmed exploitation.",
        )
    if _JNDI_GENERIC_RE.search(normalized_lower):
        return (
            0.75,
            "Suspected CVE-2021-44228 (Log4Shell) obfuscated JNDI lookup probe; candidate hypothesis only, not confirmed exploitation.",
        )
    return None


# Registry of versioned HTTP signature rules.
# Add future CVE rules here without modifying collector.py.
SIGNATURE_RULES: tuple[SignatureRule, ...] = (
    SignatureRule(
        signature_id="http-log4shell-jndi-lookup",
        rule_version="1.0.0",
        candidate_cve="CVE-2021-44228",
        classification="candidate_cve",
        match_text=_match_log4shell,
    ),
)


def inspect_http_request(
    inp: InspectionInput,
    rules: Iterable[SignatureRule] = SIGNATURE_RULES,
) -> list[SignatureMatch]:
    """Inspect bounded URL, headers, and body against registered signature rules."""
    active_rules = tuple(rules)
    if not active_rules:
        return []

    targets: list[tuple[str, str]] = []

    if inp.raw_path:
        targets.append(("url", normalize_for_inspection(inp.raw_path, MAX_INSPECT_PATH_BYTES)))

    for idx, (header_name, header_value) in enumerate(inp.headers):
        if idx >= MAX_INSPECT_HEADERS:
            break
        if not header_value:
            continue
        targets.append(
            (
                safe_header_location(header_name),
                normalize_for_inspection(header_value, MAX_INSPECT_HEADER_VALUE_BYTES),
            )
        )

    if inp.body_bytes:
        body_cap = min(inp.max_body_bytes, MAX_INSPECT_BODY_BYTES)
        body_text = inp.body_bytes[:body_cap].decode("utf-8", errors="ignore")
        if body_text:
            targets.append(("body", normalize_for_inspection(body_text, body_cap)))

    matches: list[SignatureMatch] = []
    seen: set[tuple[str, str, str]] = set()

    for location, normalized_text in targets:
        for rule in active_rules:
            result = rule.match_text(normalized_text)
            if result is None:
                continue
            dedupe_key = (rule.signature_id, rule.candidate_cve, location)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            confidence, summary = result
            matches.append(
                SignatureMatch(
                    signature_id=rule.signature_id,
                    rule_version=rule.rule_version,
                    candidate_cve=rule.candidate_cve,
                    matched_location=location,
                    confidence=confidence,
                    classification=rule.classification,
                    summary=summary,
                )
            )
            if len(matches) >= MAX_DETECTIONS_PER_EVENT:
                return matches

    return matches
