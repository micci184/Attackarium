"""Extensible, non-executing HTTP signature detection for attack techniques and candidate CVEs.

Security and design invariants:
- Strictly bounded inspection lengths and decode/deobfuscation passes (no ReDoS).
- Never executes payloads, never resolves DNS/JNDI, and never fetches attacker URLs.
- Detection records contain ONLY structured metadata (no raw payloads, no attacker
  URLs, no credentials, no raw header values).
- Clearly separates observed indicators, attack technique candidates
  (`indicator_match`), and candidate CVE associations (`candidate_cve`).
- Never infers confirmed exploitation from a signature match.
- Adding a new technique or CVE rule requires adding one SignatureRule entry to
  SIGNATURE_RULES without modifying the HTTP collector core.
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

VALID_CLASSIFICATIONS = frozenset({"indicator_match", "candidate_cve"})
VALID_MATCH_STRENGTHS = frozenset({"high", "medium", "low"})
CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")

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
class NormalizedText:
    text: str
    obfuscation_detected: bool


@dataclass(frozen=True)
class InspectionInput:
    method: str
    raw_path: str
    headers: tuple[tuple[str, str], ...]
    body_bytes: bytes
    body_truncated: bool = False
    max_body_bytes: int = MAX_INSPECT_BODY_BYTES


@dataclass(frozen=True)
class RuleHit:
    match_strength: str
    confidence: float
    indicator: str
    summary: str

    def __post_init__(self) -> None:
        if self.match_strength not in VALID_MATCH_STRENGTHS:
            raise ValueError(f"Invalid match_strength: {self.match_strength}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0: {self.confidence}")


@dataclass(frozen=True)
class SignatureMatch:
    signature_id: str
    rule_version: str
    classification: str
    attack_technique: str
    candidate_cves: tuple[str, ...]
    matched_location: str
    match_strength: str
    confidence: float
    evidence: dict[str, Any]
    references: tuple[str, ...]
    summary: str

    @property
    def candidate_cve(self) -> str | None:
        """Backward-compatible single CVE field (None when 0 or multiple CVEs)."""
        return self.candidate_cves[0] if len(self.candidate_cves) == 1 else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "rule_version": self.rule_version,
            "classification": self.classification,
            "attack_technique": self.attack_technique,
            "candidate_cves": list(self.candidate_cves),
            "candidate_cve": self.candidate_cve,
            "matched_location": self.matched_location,
            "match_strength": self.match_strength,
            "confidence": self.confidence,
            "evidence": dict(self.evidence),
            "references": list(self.references),
            "summary": self.summary,
        }


@dataclass(frozen=True)
class SignatureRule:
    signature_id: str
    rule_version: str
    attack_technique: str
    classification: str
    match_text: Callable[[NormalizedText], RuleHit | None]
    candidate_cves: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.classification not in VALID_CLASSIFICATIONS:
            raise ValueError(f"Invalid classification: {self.classification}")
        if self.classification == "candidate_cve" and not self.candidate_cves:
            raise ValueError(
                f"Rule {self.signature_id} has classification='candidate_cve' without candidate_cves"
            )
        if self.classification == "indicator_match" and self.candidate_cves:
            raise ValueError(
                f"Rule {self.signature_id} has classification='indicator_match' with candidate_cves"
            )
        for cve in self.candidate_cves:
            if not CVE_ID_RE.match(cve):
                raise ValueError(f"Rule {self.signature_id} has invalid CVE ID: {cve}")


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


def normalize_for_inspection_detailed(raw: str, max_chars: int) -> NormalizedText:
    """Bounded URL-decoding and Log4j lookup simplification for signature matching."""
    text = CONTROL_CHARS_RE.sub("", raw[:max_chars])
    obfuscated = False

    for _ in range(MAX_URL_DECODE_PASSES):
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            break
        obfuscated = True
        text = CONTROL_CHARS_RE.sub("", decoded[:max_chars])

    unicode_decoded = _decode_unicode_ascii_escapes(text)
    if unicode_decoded != text:
        obfuscated = True
        text = unicode_decoded

    for _ in range(MAX_OBFUSCATION_PASSES):
        reduced = _LOG4J_CASE_LOOKUP_RE.sub(r"\1", text)
        reduced = _LOG4J_DEFAULT_LOOKUP_RE.sub(r"\1", reduced)
        reduced = _LOG4J_DATE_LOOKUP_RE.sub(r"\1", reduced)
        if reduced == text:
            break
        obfuscated = True
        text = reduced[:max_chars]

    return NormalizedText(text=text.lower(), obfuscation_detected=obfuscated)


def normalize_for_inspection(raw: str, max_chars: int) -> str:
    """Return normalized lowercase text for signature matching."""
    return normalize_for_inspection_detailed(raw, max_chars).text


def redact_jndi_references(value: str) -> str:
    """Strip attacker JNDI expressions and callback URIs before storing metadata."""
    normalized_check = normalize_for_inspection(value, max_chars=MAX_INSPECT_HEADER_VALUE_BYTES)
    has_jndi = _JNDI_GENERIC_RE.search(normalized_check) is not None
    has_jndi_uri = _JNDI_PROTOCOL_URI_RE.search(normalized_check) is not None
    if not has_jndi and not has_jndi_uri:
        return value

    redacted = _JNDI_PROTOCOL_URI_RE.sub("[REDACTED_JNDI_URI]", value)
    if has_jndi:
        redacted = _JNDI_EXPRESSION_RE.sub("[REDACTED_JNDI]", redacted)

    # Re-verify after literal substitution: if an encoded or obfuscated JNDI
    # reference remains (e.g. mixed with a literal ${...}), redact the whole value.
    recheck = normalize_for_inspection(redacted, max_chars=MAX_INSPECT_HEADER_VALUE_BYTES)
    if _JNDI_GENERIC_RE.search(recheck) is not None:
        return "[REDACTED_JNDI]"
    if _JNDI_PROTOCOL_URI_RE.search(recheck) is not None:
        return "[REDACTED_JNDI_URI]"
    return redacted


def _match_log4shell(normalized: NormalizedText) -> RuleHit | None:
    if _JNDI_WITH_SCHEME_RE.search(normalized.text):
        return RuleHit(
            match_strength="high",
            confidence=0.9,
            indicator="jndi_lookup_with_scheme",
            summary=(
                "Suspected CVE-2021-44228 (Log4Shell) JNDI lookup probe; "
                "candidate hypothesis only, not confirmed exploitation."
            ),
        )
    if _JNDI_GENERIC_RE.search(normalized.text):
        return RuleHit(
            match_strength="medium",
            confidence=0.75,
            indicator="jndi_lookup_obfuscated_scheme",
            summary=(
                "Suspected CVE-2021-44228 (Log4Shell) obfuscated JNDI lookup probe; "
                "candidate hypothesis only, not confirmed exploitation."
            ),
        )
    return None


# Registry of versioned HTTP signature rules.
# Add future attack-technique or CVE rules here without modifying collector.py.
SIGNATURE_RULES: tuple[SignatureRule, ...] = (
    SignatureRule(
        signature_id="http-log4shell-jndi-lookup",
        rule_version="1.1.0",
        attack_technique="jndi_injection",
        classification="candidate_cve",
        candidate_cves=("CVE-2021-44228",),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2021-44228",),
        match_text=_match_log4shell,
    ),
)


def derive_signature_attack_category(detections: Iterable[SignatureMatch]) -> str | None:
    """Map detections to existing attack_category values without claiming exploitation."""
    has_indicator = False
    for match in detections:
        if match.classification == "candidate_cve":
            return "suspected_cve_probe"
        if match.classification == "indicator_match":
            has_indicator = True
    return "web_attack_attempt" if has_indicator else None


def inspect_http_request(
    inp: InspectionInput,
    rules: Iterable[SignatureRule] = SIGNATURE_RULES,
) -> list[SignatureMatch]:
    """Inspect bounded URL, headers, and body against registered signature rules."""
    active_rules = tuple(rules)
    if not active_rules:
        return []

    targets: list[tuple[str, NormalizedText]] = []

    if inp.raw_path:
        targets.append(
            ("url", normalize_for_inspection_detailed(inp.raw_path, MAX_INSPECT_PATH_BYTES))
        )

    for idx, (header_name, header_value) in enumerate(inp.headers):
        if idx >= MAX_INSPECT_HEADERS:
            break
        if not header_value:
            continue
        targets.append(
            (
                safe_header_location(header_name),
                normalize_for_inspection_detailed(header_value, MAX_INSPECT_HEADER_VALUE_BYTES),
            )
        )

    if inp.body_bytes:
        body_cap = min(inp.max_body_bytes, MAX_INSPECT_BODY_BYTES)
        body_text = inp.body_bytes[:body_cap].decode("utf-8", errors="ignore")
        if body_text:
            targets.append(("body", normalize_for_inspection_detailed(body_text, body_cap)))

    matches: list[SignatureMatch] = []
    seen: set[tuple[str, tuple[str, ...], str]] = set()

    for location, normalized in targets:
        for rule in active_rules:
            hit = rule.match_text(normalized)
            if hit is None:
                continue
            dedupe_key = (rule.signature_id, rule.candidate_cves, location)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            matches.append(
                SignatureMatch(
                    signature_id=rule.signature_id,
                    rule_version=rule.rule_version,
                    classification=rule.classification,
                    attack_technique=rule.attack_technique,
                    candidate_cves=rule.candidate_cves,
                    matched_location=location,
                    match_strength=hit.match_strength,
                    confidence=hit.confidence,
                    evidence={
                        "indicator": hit.indicator,
                        "obfuscation_detected": normalized.obfuscation_detected,
                    },
                    references=rule.references,
                    summary=hit.summary,
                )
            )
            if len(matches) >= MAX_DETECTIONS_PER_EVENT:
                return matches

    return matches
