"""
┌─────────────────────────────────────────────────────────────┐
│              Local Clipboard Redactor  v0.0                 │
│                                                             │
│  Hotkey  →  reads clipboard  →  redacts  →  ready to paste  │
│                                                             │
│  Layer 1 — Regex    : API keys, emails, phones, JWTs …      │
│  Layer 2 — NER      : PERSON / ORG near trigger words       │
└─────────────────────────────────────────────────────────────┘

Hotkey (default):
    Windows / Linux  →  Ctrl + Shift + X
    Mac              →  change HOTKEY below to  <cmd>+<shift>+x

Install:
    pip install pynput pyperclip plyer transformers torch

Run:
    python redactor.py
"""

import os
import re
import threading
import unicodedata

import pyperclip
from pynput import keyboard

# ── Optional toast notifications ──────────────────────────────────────────────
try:
    from plyer import notification
    _NOTIFY = True
except ImportError:
    _NOTIFY = False

# ── Optional NER (skipped gracefully if torch / transformers not installed) ───
try:
    from transformers import pipeline as hf_pipeline
    _NER_AVAILABLE = True
except ImportError:
    _NER_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG  — all tuneable knobs in one place
# ══════════════════════════════════════════════════════════════════════════════

HOTKEY = "<ctrl>+<shift>+x"   # ← Mac users: change to "<cmd>+<shift>+x"

# ── NER settings ──────────────────────────────────────────────────────────────

#: Number of words to scan before AND after a detected entity for trigger words
NER_WINDOW_SIZE: int = 5

#: Ignore entity predictions below this confidence score
NER_MIN_CONFIDENCE: float = 0.85

#: Random bytes appended as hex to each NER placeholder  →  2 bytes = 4 hex chars
NER_TOKEN_HEX_BYTES: int = 2

#: dslim/bert-base-NER outputs "PER" / "ORG" — map to human-readable labels
NER_LABEL_MAP: dict[str, str] = {
    "PER": "PERSON",
    "ORG": "ORG",
}

#: An entity is only masked when one of these words appears in its context window
NER_TRIGGER_WORDS: frozenset[str] = frozenset({
    # Possessives / ownership
    "our", "my", "companys",          # "company's" normalises → "companys"
    # C-suite / leadership titles
    "ceo", "cto", "cfo", "coo",
    "vp", "svp", "evp",
    "director", "head", "chief",
    "founder", "president", "officer",
    # General role / relationship words
    "manager", "lead", "partner",
    "employee", "colleague", "hire", "hired", "joining",
    "client", "customer", "vendor", "contractor",
})

#: Organisations that are always public knowledge — never mask them
NER_PUBLIC_ORG_ALLOWLIST: frozenset[str] = frozenset({
    "google", "microsoft", "apple", "amazon", "meta", "openai",
    "anthropic", "nvidia", "tesla", "twitter", "linkedin", "github",
    "facebook", "netflix", "adobe", "oracle", "ibm", "intel",
    "samsung", "huawei", "tata", "infosys", "wipro", "accenture",
    "deloitte", "mckinsey", "salesforce", "atlassian", "slack",
    "zoom", "dropbox", "spotify", "airbnb", "uber", "lyft",
})


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — REGEX  (structural secrets, always sensitive)
# ══════════════════════════════════════════════════════════════════════════════

# Each entry:  (compiled_pattern, placeholder_prefix)
_REGEX_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
     "JWT"),

    (re.compile(r"\b(AKIA|AIPA|ASIA)[A-Z0-9]{16}\b"),
     "AWS_KEY"),

    (re.compile(r"\b(sk|pk|api|key|token|secret)[_\-]?[A-Za-z0-9_\-]{16,}\b"),
     "API_KEY"),

    # Requires explicit user:pass — [^:@\s]+ prevents the colon in :// from matching
    (re.compile(r"[a-z]+://[^:@\s]+:[^@\s]+@[^\s]+"),
     "CONN_STRING"),

    (re.compile(r"(?i)(password|passwd|pwd|secret)\s*[:=]\s*\S+"),
     "PASSWORD"),

    # Negative lookbehind (?<![/\w]) prevents firing on URL-embedded user@host segments
    (re.compile(r"(?<![/\w])\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
     "EMAIL"),

    (re.compile(r"\b(\+?[0-9]{1,3}[\s\-\.]?)?(\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4})\b"),
     "PHONE"),

    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
     "IP_ADDRESS"),

    (re.compile(r"\b(?:\d[ \-]?){13,19}\b"),
     "CREDIT_CARD"),
]


def _redact_regex(text: str) -> tuple[str, dict[str, str]]:
    """
    Apply all regex patterns left-to-right.
    Returns (redacted_text, mapping) where mapping is { placeholder: original }.
    Identical values are deduplicated — same value always gets the same placeholder.
    """
    mapping: dict[str, str] = {}   # placeholder → original
    _value_to_ph: dict[str, str] = {}  # original → placeholder  (dedup index)
    counters: dict[str, int] = {}

    def _replace(match: re.Match, prefix: str) -> str:
        original = match.group(0)
        if original in _value_to_ph:
            return _value_to_ph[original]
        counters[prefix] = counters.get(prefix, 0) + 1
        ph = f"[{prefix}_{counters[prefix]}]"
        mapping[ph] = original
        _value_to_ph[original] = ph
        return ph

    redacted = text
    for pattern, prefix in _REGEX_PATTERNS:
        redacted = pattern.sub(lambda m, p=prefix: _replace(m, p), redacted)

    return redacted, mapping


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — NER  (context-sensitive PERSON / ORG detection)
# ══════════════════════════════════════════════════════════════════════════════

_ner_pipeline = None   # singleton — loaded once


def warm_up_model() -> None:
    """Load the NER model into memory. Call once at startup."""
    global _ner_pipeline
    if not _NER_AVAILABLE:
        print("[NER] transformers / torch not installed — NER layer disabled.")
        return
    if _ner_pipeline is None:
        print("[NER] Loading model (first run, ~3–8 s)…")
        _ner_pipeline = hf_pipeline(
            task="ner",
            model="dslim/bert-base-NER",
            aggregation_strategy="simple",
        )
        print("[NER] Model ready.")


def _ner_normalize(word: str) -> str:
    """Lowercase + strip punctuation + NFKD unicode.  'CEO,' → 'ceo'"""
    word = unicodedata.normalize("NFKD", word).lower()
    return re.sub(r"[^\w\s]", "", word).strip()


def _ner_context_words(text: str, start: int, end: int) -> list[str]:
    """Return words within WINDOW_SIZE before AND after the entity span."""
    before = text[:start].split()[-NER_WINDOW_SIZE:]
    after  = text[end:].split()[:NER_WINDOW_SIZE]
    return before + after


def _ner_make_token(label: str) -> str:
    """Return a unique semantic token, e.g. ⟪PERSON·a1b2⟫"""
    suffix = os.urandom(NER_TOKEN_HEX_BYTES).hex()
    return f"⟪{label}·{suffix}⟫"


def _redact_entities(text: str) -> tuple[str, dict[str, str]]:
    """
    Detect PERSON / ORG entities and mask those that appear near a trigger word.
    Returns (redacted_text, mapping).
    No-ops silently when the NER model is unavailable.
    """
    if not _ner_pipeline or not text.strip():
        return text, {}

    raw = _ner_pipeline(text)

    # Filter by target type and confidence threshold
    entities = [
        e for e in raw
        if e["entity_group"] in NER_LABEL_MAP
        and e["score"] >= NER_MIN_CONFIDENCE
    ]

    # Sort descending by start so right-to-left substitution keeps offsets valid
    entities.sort(key=lambda e: e["start"], reverse=True)

    dedup: dict[str, str] = {}    # normalised_text → token
    mapping: dict[str, str] = {}  # token → original text
    redacted = text

    for ent in entities:
        start, end  = ent["start"], ent["end"]
        label       = NER_LABEL_MAP[ent["entity_group"]]
        original    = text[start:end]   # use char offsets — preserves exact casing

        # Skip public orgs (Google, Microsoft, etc.)
        if label == "ORG" and _ner_normalize(original) in NER_PUBLIC_ORG_ALLOWLIST:
            continue

        # Only mask when a trigger word appears in the context window
        ctx = _ner_context_words(text, start, end)
        if not any(_ner_normalize(w) in NER_TRIGGER_WORDS for w in ctx):
            continue

        # Deduplicate: same entity text → same token
        key = _ner_normalize(original)
        if key not in dedup:
            token = _ner_make_token(label)
            dedup[key] = token
            mapping[token] = original
        else:
            token = dedup[key]

        redacted = redacted[:start] + token + redacted[end:]

    return redacted, mapping


# ══════════════════════════════════════════════════════════════════════════════
# COMBINED REDACT PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def redact(text: str) -> tuple[str, dict[str, str]]:
    """
    Run both redaction layers in sequence.

    Layer 1 (regex)  runs first — fast, zero false positives on structural secrets.
    Layer 2 (NER)    runs on the already-redacted text so the model never sees
                     secrets that Layer 1 already replaced.

    Returns (redacted_text, combined_mapping).
    """
    # Layer 1 — regex
    text_after_regex, regex_mapping = _redact_regex(text)

    # Layer 2 — NER  (receives pre-sanitised text from Layer 1)
    text_after_ner, ner_mapping = _redact_entities(text_after_regex)

    combined_mapping = {**regex_mapping, **ner_mapping}
    return text_after_ner, combined_mapping


# ══════════════════════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════════════════

def _notify(title: str, message: str) -> None:
    print(f"\n[{title}] {message}")
    if _NOTIFY:
        try:
            notification.notify(
                title=title,
                message=message,
                app_name="Clipboard Redactor",
                timeout=3,
            )
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# HOTKEY HANDLER
# ══════════════════════════════════════════════════════════════════════════════

def _handle_hotkey() -> None:
    """Runs in a background thread — never blocks the hotkey listener."""

    def _run():
        original = pyperclip.paste()

        if not original.strip():
            _notify("Redactor", "Clipboard is empty — nothing to redact.")
            return

        redacted, mapping = redact(original)

        if not mapping:
            _notify("Redactor ✓", "No sensitive data found.")
            return

        pyperclip.copy(redacted)

        # ── Console log — full mapping for reference ───────────────────────────
        print("\n── Redaction map (local only, never leaves this machine) ──")
        for ph, original_val in mapping.items():
            print(f"  {ph:30s}  ←  {original_val}")
        print("────────────────────────────────────────────────────────────")

        # ── Toast: concise summary ─────────────────────────────────────────────
        regex_phs = [k for k in mapping if k.startswith("[")]
        ner_phs   = [k for k in mapping if k.startswith("⟪")]
        parts = []
        if regex_phs:
            parts.append(f"{len(regex_phs)} structural")
        if ner_phs:
            parts.append(f"{len(ner_phs)} entity")
        summary = "  •  ".join(parts) + " redaction(s)"

        _notify(
            f"Redactor ✓  —  {len(mapping)} item{'s' if len(mapping) > 1 else ''} masked",
            summary,
        )

    threading.Thread(target=_run, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    print("──────────────────────────────────────────")
    print("  Local Clipboard Redactor  v0.0")
    print("──────────────────────────────────────────")

    # Load NER model in background so the app feels instant to start
    threading.Thread(target=warm_up_model, daemon=True).start()

    print(f"  Hotkey  : {HOTKEY}")
    print("  Flow    : Copy text → press hotkey → paste redacted text")
    print("  Layers  : [1] Regex  [2] NER (loads in background)")
    print("──────────────────────────────────────────\n")

    with keyboard.GlobalHotKeys({HOTKEY: _handle_hotkey}) as listener:
        listener.join()


if __name__ == "__main__":
    main()