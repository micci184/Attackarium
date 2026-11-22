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

# 1. Log4Shell (CVE-2021-44228)
_JNDI_WITH_SCHEME_RE = re.compile(
    r"\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|corba|nds|http|https)\s*:"
)
_JNDI_GENERIC_RE = re.compile(r"\$\{\s*jndi\s*:")

# 2. SQL Injection (generic technique, no CVE)
_SQL_COMMENT_RE = re.compile(r"/\*[^*]{0,32}\*/")
_SQLI_UNION_SELECT_RE = re.compile(r"\bunion(?:[\s+]{1,16}all)?[\s+]{1,16}select\b")
_SQLI_TIME_BASED_RE = re.compile(
    r"(?:\b(?:sleep|benchmark)[\s+]{0,16}\([\s+]{0,16}\d{1,4}|\bwaitfor[\s+]{1,16}delay[\s+]{1,16}['\"])"
)
_SQLI_INFO_SCHEMA_RE = re.compile(r"\binformation_schema\.(?:tables|columns|schemata)\b")
_SQLI_TAUTOLOGY_RE = re.compile(
    r"(?:'|\"|\))[\s+]{0,16}or[\s+]{1,16}(?:'1'[\s+]{0,8}=[\s+]{0,8}'1'|\"1\"[\s+]{0,8}=[\s+]{0,8}\"1\"|1[\s+]{0,8}=[\s+]{0,8}1)[\s+]{0,8}(?:--|#|$)"
)

# 3. Path Traversal (generic technique, no CVE)
# Use fixed repetition counts ({2} / {3}) to avoid catastrophic backtracking on
# adversarial repeated "../" sequences.
_TRAVERSAL_SENSITIVE_TARGET_RE = re.compile(
    r"(?:\.\.[/\\]){2}[^\s]{0,64}(?:etc/(?:passwd|shadow|hosts)|win\.ini|boot\.ini|proc/self/)"
)
_TRAVERSAL_DEEP_RE = re.compile(r"(?:\.\.[/\\]){3}")

# 4. Command Injection (generic technique, no CVE)
_CMD_INJECTION_RE = re.compile(
    r"(?:;|\|\||&&|\||`|\$\()\s{0,16}"
    r"(?:id|uname|whoami|wget|curl|nc|bash|sh|/bin/sh|/bin/bash|cat\s+/etc/passwd|powershell|cmd\.exe)"
    r"(?=\s|$|[;|&)`'\"/])"
)

# 5. Apache HTTP Server Path Traversal (CVE-2021-41773 / CVE-2021-42013)
_APACHE_PREFIX_RE = re.compile(r"/(?:cgi-bin|icons)/")
_APACHE_ENCODED_DOT_RE = re.compile(r"(?:\.%2e|%2e\.|%2e%2e|%%32%65|%252e)")
_APACHE_DECODED_TRAVERSAL_RE = re.compile(r"(?:\.\./|/bin/sh|/etc/passwd)")

# 6. Spring4Shell (CVE-2022-22965)
_SPRING4SHELL_PIPELINE_RE = re.compile(
    r"class\.module\.classloader\.resources\.context\.parent\.pipeline\.first\."
)
_SPRING4SHELL_CLASSLOADER_RE = re.compile(
    r"class\.module\.classloader[^\r\n]{0,128}(?:pattern|suffix|directory|prefix|filedateformat)"
)

# 7. PHP-CGI Argument Injection (CVE-2024-4577)
_PHP_CGI_SOFT_HYPHEN_RE = re.compile(
    r"%ad(?:\s|\+|%20){0,4}d(?:\b|allow_url_include|auto_prepend_file)"
)
_PHP_CGI_DANGEROUS_DIRECTIVE_RE = re.compile(
    r"(?:allow_url_include|auto_prepend_file)"
)

# Redaction helpers to strip attacker-controlled expressions/URLs from stored metadata.
_JNDI_EXPRESSION_RE = re.compile(r"\$\{[^\r\n]{0,512}\}")
_JNDI_PROTOCOL_URI_RE = re.compile(
    r"(?:ldap|ldaps|rmi|iiop|corba|nds)://[^\s'\"}\])<>,;]+",
    re.IGNORECASE,
)
_CALLBACK_URL_RE = re.compile(
    r"(?:https?|ftp|tftp)://[^\s'\"}\])<>,;|`&]+",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class NormalizedText:
    text: str
    obfuscation_detected: bool
    raw_lower: str = ""


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
    raw_clean = CONTROL_CHARS_RE.sub("", raw[:max_chars])
    text = raw_clean
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

    return NormalizedText(
        text=text.lower(),
        obfuscation_detected=obfuscated,
        raw_lower=raw_clean.lower(),
    )


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


def redact_attacker_references(value: str) -> str:
    """Strip attacker JNDI references and command-injection callback URLs."""
    redacted = redact_jndi_references(value)
    normalized = normalize_for_inspection(redacted, max_chars=MAX_INSPECT_HEADER_VALUE_BYTES)
    if _CMD_INJECTION_RE.search(normalized) is not None:
        replaced = _CALLBACK_URL_RE.sub("[REDACTED_URL]", redacted)
        recheck = normalize_for_inspection(replaced, max_chars=MAX_INSPECT_HEADER_VALUE_BYTES)
        if _CALLBACK_URL_RE.search(recheck) is not None:
            return "[REDACTED_CMD_PAYLOAD]"
        return replaced
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


def _match_sqli(normalized: NormalizedText) -> RuleHit | None:
    # Strip inline SQL comments (e.g. UN/**/ION -> UNION) without touching other rules.
    collapsed = _SQL_COMMENT_RE.sub("", normalized.text)
    spaced = _SQL_COMMENT_RE.sub(" ", normalized.text)
    candidates = (normalized.text, collapsed, spaced)

    for text in candidates:
        if _SQLI_UNION_SELECT_RE.search(text):
            return RuleHit(
                match_strength="high",
                confidence=0.85,
                indicator="sqli_union_select",
                summary=(
                    "Observed SQL injection indicator (UNION SELECT syntax); "
                    "no specific CVE inferred and exploitation outcome is unknown."
                ),
            )
        if _SQLI_TIME_BASED_RE.search(text):
            return RuleHit(
                match_strength="high",
                confidence=0.85,
                indicator="sqli_time_delay_function",
                summary=(
                    "Observed SQL injection indicator (time-delay function syntax); "
                    "no specific CVE inferred and exploitation outcome is unknown."
                ),
            )
        if _SQLI_INFO_SCHEMA_RE.search(text):
            return RuleHit(
                match_strength="high",
                confidence=0.8,
                indicator="sqli_information_schema",
                summary=(
                    "Observed SQL injection indicator (information_schema reference); "
                    "no specific CVE inferred and exploitation outcome is unknown."
                ),
            )
        if _SQLI_TAUTOLOGY_RE.search(text):
            return RuleHit(
                match_strength="medium",
                confidence=0.7,
                indicator="sqli_boolean_tautology",
                summary=(
                    "Observed SQL injection indicator (boolean tautology syntax); "
                    "no specific CVE inferred and exploitation outcome is unknown."
                ),
            )
    return None


def _match_path_traversal(normalized: NormalizedText) -> RuleHit | None:
    if _TRAVERSAL_SENSITIVE_TARGET_RE.search(normalized.text):
        return RuleHit(
            match_strength="high",
            confidence=0.85,
            indicator="path_traversal_sensitive_file",
            summary=(
                "Observed path traversal indicator targeting a common system file; "
                "no specific CVE inferred and exploitation outcome is unknown."
            ),
        )
    if _TRAVERSAL_DEEP_RE.search(normalized.text):
        return RuleHit(
            match_strength="medium",
            confidence=0.7,
            indicator="path_traversal_repeated_parent_segments",
            summary=(
                "Observed repeated parent-directory traversal sequence; "
                "no specific CVE inferred and exploitation outcome is unknown."
            ),
        )
    return None


def _match_command_injection(normalized: NormalizedText) -> RuleHit | None:
    if _CMD_INJECTION_RE.search(normalized.text):
        return RuleHit(
            match_strength="high",
            confidence=0.85,
            indicator="shell_metacharacter_with_command",
            summary=(
                "Observed OS command injection indicator (shell metacharacter and command token); "
                "no specific CVE inferred and exploitation outcome is unknown."
            ),
        )
    return None


def _match_apache_path_traversal(normalized: NormalizedText) -> RuleHit | None:
    if (
        _APACHE_PREFIX_RE.search(normalized.raw_lower)
        and _APACHE_ENCODED_DOT_RE.search(normalized.raw_lower)
        and _APACHE_DECODED_TRAVERSAL_RE.search(normalized.text)
    ):
        return RuleHit(
            match_strength="high",
            confidence=0.85,
            indicator="apache_cgi_encoded_dot_traversal",
            summary=(
                "Suspected Apache HTTP Server path traversal probe (CVE-2021-41773 / CVE-2021-42013); "
                "candidate CVEs only, not confirmed exploitation."
            ),
        )
    return None


def _match_spring4shell(normalized: NormalizedText) -> RuleHit | None:
    if _SPRING4SHELL_PIPELINE_RE.search(normalized.text):
        return RuleHit(
            match_strength="high",
            confidence=0.9,
            indicator="spring_classloader_pipeline_binding",
            summary=(
                "Suspected CVE-2022-22965 (Spring4Shell) ClassLoader property-binding probe; "
                "candidate hypothesis only, not confirmed exploitation."
            ),
        )
    if _SPRING4SHELL_CLASSLOADER_RE.search(normalized.text):
        return RuleHit(
            match_strength="medium",
            confidence=0.75,
            indicator="spring_classloader_accesslog_binding",
            summary=(
                "Suspected CVE-2022-22965 (Spring4Shell) ClassLoader probe; "
                "candidate hypothesis only, not confirmed exploitation."
            ),
        )
    return None


def _match_php_cgi_arg_injection(normalized: NormalizedText) -> RuleHit | None:
    if _PHP_CGI_SOFT_HYPHEN_RE.search(
        normalized.raw_lower
    ) and _PHP_CGI_DANGEROUS_DIRECTIVE_RE.search(normalized.text):
        return RuleHit(
            match_strength="high",
            confidence=0.9,
            indicator="php_cgi_soft_hyphen_directive_injection",
            summary=(
                "Suspected CVE-2024-4577 (PHP-CGI argument injection) probe via soft-hyphen directive; "
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
    SignatureRule(
        signature_id="http-apache-path-traversal-cve-2021-41773",
        rule_version="1.0.0",
        attack_technique="path_traversal",
        classification="candidate_cve",
        candidate_cves=("CVE-2021-41773", "CVE-2021-42013"),
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        ),
        match_text=_match_apache_path_traversal,
    ),
    SignatureRule(
        signature_id="http-spring4shell-cve-2022-22965",
        rule_version="1.0.0",
        attack_technique="rce",
        classification="candidate_cve",
        candidate_cves=("CVE-2022-22965",),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2022-22965",),
        match_text=_match_spring4shell,
    ),
    SignatureRule(
        signature_id="http-php-cgi-arg-injection-cve-2024-4577",
        rule_version="1.0.0",
        attack_technique="rce",
        classification="candidate_cve",
        candidate_cves=("CVE-2024-4577",),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-4577",),
        match_text=_match_php_cgi_arg_injection,
    ),
    SignatureRule(
        signature_id="http-sqli-attempt",
        rule_version="1.0.0",
        attack_technique="sql_injection",
        classification="indicator_match",
        candidate_cves=(),
        references=("https://owasp.org/www-community/attacks/SQL_Injection",),
        match_text=_match_sqli,
    ),
    SignatureRule(
        signature_id="http-path-traversal-attempt",
        rule_version="1.0.0",
        attack_technique="path_traversal",
        classification="indicator_match",
        candidate_cves=(),
        references=("https://owasp.org/www-community/attacks/Path_Traversal",),
        match_text=_match_path_traversal,
    ),
    SignatureRule(
        signature_id="http-cmd-injection-attempt",
        rule_version="1.0.0",
        attack_technique="command_injection",
        classification="indicator_match",
        candidate_cves=(),
        references=("https://owasp.org/www-community/attacks/Command_Injection",),
        match_text=_match_command_injection,
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
