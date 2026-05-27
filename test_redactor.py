"""
Redactor Test Suite
────────────────────
Tests every edge case category and shows WHICH layer caught each match.

Run:
    python test_redactor.py
    python test_redactor.py --no-ner     # skip NER (faster, no model needed)
    python test_redactor.py --verbose    # show full redacted text too
"""

import sys
import argparse
import textwrap
import time

# ── pull the two layers directly from redactor.py ─────────────────────────────
from redactor import (
    _redact_regex,
    _redact_entities,
    warm_up_model,
    _NER_AVAILABLE,
)


# ══════════════════════════════════════════════════════════════════════════════
# LAYER-ATTRIBUTED REDACTION  (test-only helper)
# ══════════════════════════════════════════════════════════════════════════════

def redact_with_attribution(text: str) -> dict:
    """
    Run both layers separately and return a structured result:
    {
      "original":    str,
      "redacted":    str,
      "regex_hits":  { placeholder: original },
      "ner_hits":    { placeholder: original },
      "all_hits":    { placeholder: original },
    }
    """
    after_regex, regex_map = _redact_regex(text)
    after_ner,   ner_map   = _redact_entities(after_regex)

    return {
        "original":   text,
        "redacted":   after_ner,
        "regex_hits": regex_map,
        "ner_hits":   ner_map,
        "all_hits":   {**regex_map, **ner_map},
    }


# ══════════════════════════════════════════════════════════════════════════════
# TEST CASE DEFINITIONS
# Each case:
#   text          – input string
#   expect_regex  – True / False / None (None = don't assert)
#   expect_ner    – True / False / None
#   note          – why this case matters
# ══════════════════════════════════════════════════════════════════════════════

CASES = [

    # ── EMAILS ────────────────────────────────────────────────────────────────
    dict(
        group="Email",
        text="Reach me at john.doe@company.com for details.",
        expect_regex=True, expect_ner=None,
        note="Standard email",
    ),
    dict(
        group="Email",
        text="Email support@google.com for help.",
        expect_regex=True, expect_ner=None,
        note="Public support email — still a credential, should be masked",
    ),
    dict(
        group="Email",
        text="the format is user@domain.tld — just an example",
        expect_regex=True, expect_ner=None,
        note="Example email — regex can't know it's hypothetical (known limitation)",
    ),

    # ── API KEYS & TOKENS ─────────────────────────────────────────────────────
    dict(
        group="API Keys",
        text="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123XYZ",
        expect_regex=True, expect_ner=None,
        note="JWT in Authorization header",
    ),
    dict(
        group="API Keys",
        text="export OPENAI_API_KEY=sk-abc123DEFghi456JKLmno789",
        expect_regex=True, expect_ner=None,
        note="API key in shell export",
    ),
    dict(
        group="API Keys",
        text="AKIAIOSFODNN7EXAMPLE is an AWS access key",
        expect_regex=True, expect_ner=None,
        note="AWS key ID",
    ),
    dict(
        group="API Keys",
        text="The token prefix is 'sk-' followed by random chars",
        expect_regex=False, expect_ner=None,
        note="Describing key format — no actual key present",
    ),

    # ── PASSWORDS & CONNECTION STRINGS ────────────────────────────────────────
    dict(
        group="Credentials",
        text="password=hunter2 is a classic weak password",
        expect_regex=True, expect_ner=None,
        note="Password in key=value form",
    ),
    dict(
        group="Credentials",
        text="Connect using mongodb://admin:s3cr3t@db.prod.internal:27017/mydb",
        expect_regex=True, expect_ner=None,
        note="MongoDB connection string with embedded credentials",
    ),
    dict(
        group="Credentials",
        text="postgres://readonly_user@db.example.com/analytics",
        expect_regex=False, expect_ner=None,
        note="Connection string without password — no credentials embedded",
    ),

    # ── PHONE NUMBERS ─────────────────────────────────────────────────────────
    dict(
        group="Phone",
        text="Call us at +1-800-555-0199",
        expect_regex=True, expect_ner=None,
        note="US phone with country code",
    ),
    dict(
        group="Phone",
        text="My number is (415) 555-2671, call anytime",
        expect_regex=True, expect_ner=None,
        note="US phone with area code in parens",
    ),
    dict(
        group="Phone",
        text="IPv4 address 192.168.1.100",
        expect_regex=True, expect_ner=None,
        note="IP address — not a phone, different pattern",
    ),

    # ── NER: SHOULD MASK ──────────────────────────────────────────────────────
    dict(
        group="NER — should mask",
        text="our CEO John Smith approved the roadmap",
        expect_regex=False, expect_ner=True,
        note="Trigger before entity",
    ),
    dict(
        group="NER — should mask",
        text="John Smith, our CTO, signed off on the architecture",
        expect_regex=False, expect_ner=True,
        note="Trigger AFTER entity (bidirectional window)",
    ),
    dict(
        group="NER — should mask",
        text="hired Sarah Connor as VP of Engineering last week",
        expect_regex=False, expect_ner=True,
        note="Role title trigger + PERSON",
    ),
    dict(
        group="NER — should mask",
        text="my client Acme Corp needs a revised proposal by Friday",
        expect_regex=False, expect_ner=True,
        note="'my client' triggers ORG masking",
    ),
    dict(
        group="NER — should mask",
        text="our CEO John Smith met with John Smith again yesterday",
        expect_regex=False, expect_ner=True,
        note="Same entity twice — should produce ONE placeholder (dedup)",
    ),
    dict(
        group="NER — should mask",
        text="the contractor David Lee submitted an invoice",
        expect_regex=False, expect_ner=True,
        note="'contractor' is a trigger word",
    ),

    # ── NER: SHOULD NOT MASK ──────────────────────────────────────────────────
    dict(
        group="NER — should NOT mask",
        text="tell me about India",
        expect_regex=False, expect_ner=False,
        note="Country name — no trigger, not sensitive",
    ),
    dict(
        group="NER — should NOT mask",
        text="Google released a new model yesterday",
        expect_regex=False, expect_ner=False,
        note="Public org, no trigger",
    ),
    dict(
        group="NER — should NOT mask",
        text="who is the CEO of Microsoft?",
        expect_regex=False, expect_ner=False,
        note="Public org in question — no possessive trigger",
    ),
    dict(
        group="NER — should NOT mask",
        text="the book mentions a character named James Bond",
        expect_regex=False, expect_ner=False,
        note="Fictional character — no trigger",
    ),
    dict(
        group="NER — should NOT mask",
        text="Napoleon Bonaparte was exiled to Elba in 1814",
        expect_regex=False, expect_ner=False,
        note="Historical figure — no trigger",
    ),
    dict(
        group="NER — should NOT mask",
        text="Einstein developed the theory of relativity",
        expect_regex=False, expect_ner=False,
        note="Famous person, general knowledge question",
    ),
    dict(
        group="NER — should NOT mask",
        text="I'm reading a book by Malcolm Gladwell",
        expect_regex=False, expect_ner=False,
        note="Public figure, no sensitivity trigger",
    ),

    # ── MIXED: BOTH LAYERS HIT ────────────────────────────────────────────────
    dict(
        group="Mixed — both layers",
        text="our CTO Jane Doe can be reached at jane@acme.com, key=sk-XYZsecret12345678",
        expect_regex=True, expect_ner=True,
        note="Email + API key (regex) AND person (NER) all in one prompt",
    ),
    dict(
        group="Mixed — both layers",
        text="connect to postgres://admin:pass@db.internal/prod, ask our DBA Mike Johnson",
        expect_regex=True, expect_ner=True,
        note="Connection string (regex) + person with trigger (NER)",
    ),

    # ── TRICKY / ADVERSARIAL ──────────────────────────────────────────────────
    dict(
        group="Tricky",
        text="the CEO approved it",
        expect_regex=False, expect_ner=False,
        note="Role title but NO person named — nothing to mask",
    ),
    dict(
        group="Tricky",
        text="our team worked hard this quarter",
        expect_regex=False, expect_ner=False,
        note="Possessive 'our' but no entity detected",
    ),
    dict(
        group="Tricky",
        text="What if someone at our company earned $500k?",
        expect_regex=False, expect_ner=False,
        note="Hypothetical phrasing — no named entity, nothing to mask",
    ),
    dict(
        group="Tricky",
        text="We use AWS and Google Cloud for infrastructure",
        expect_regex=False, expect_ner=False,
        note="Both are public orgs — should not be masked",
    ),
    dict(
        group="Tricky",
        text="Reply-To: noreply@newsletter.io",
        expect_regex=True, expect_ner=None,
        note="Email in a header field",
    ),
    dict(
        group="Tricky",
        text="password strength: use at least 12 chars",
        expect_regex=False, expect_ner=None,
        note="'password' in advice context — no key=value, should not trigger",
    ),
    dict(
        group="Tricky",
        text="our new hire starts Monday",
        expect_regex=False, expect_ner=False,
        note="Trigger word 'hire' but no named entity",
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════════════════════════════════════

PASS  = "✓"
FAIL  = "✗"
SKIP  = "–"
WARN  = "?"

def run(verbose: bool = False, skip_ner: bool = False) -> None:
    if not skip_ner and _NER_AVAILABLE:
        print("\nLoading NER model…")
        t0 = time.time()
        warm_up_model()
        print(f"Model ready in {time.time() - t0:.1f}s\n")
    elif skip_ner:
        print("\n[--no-ner] Skipping NER layer.\n")
    else:
        print("\n[NER unavailable] Install transformers + torch to enable NER tests.\n")

    groups_seen = set()
    total = passed = failed = skipped = 0
    failures = []

    for case in CASES:
        group = case["group"]
        if group not in groups_seen:
            print(f"\n{'─'*60}")
            print(f"  {group}")
            print(f"{'─'*60}")
            groups_seen.add(group)

        result = redact_with_attribution(case["text"])
        regex_hit = bool(result["regex_hits"])
        ner_hit   = bool(result["ner_hits"]) if not skip_ner else None

        # ── evaluate assertions ───────────────────────────────────────────────
        regex_status = SKIP
        ner_status   = SKIP
        case_passed  = True

        if case["expect_regex"] is not None:
            if regex_hit == case["expect_regex"]:
                regex_status = PASS
            else:
                regex_status = FAIL
                case_passed = False

        if not skip_ner and case["expect_ner"] is not None:
            if ner_hit == case["expect_ner"]:
                ner_status = PASS
            else:
                ner_status = FAIL
                case_passed = False

        total += 1
        if regex_status == FAIL or ner_status == FAIL:
            failed += 1
            failures.append(case)
        elif regex_status == SKIP and ner_status == SKIP:
            skipped += 1
        else:
            passed += 1

        # ── print row ─────────────────────────────────────────────────────────
        overall = PASS if case_passed else FAIL
        note    = case["note"]
        text_preview = textwrap.shorten(case["text"], width=55, placeholder="…")

        print(f"\n  [{overall}] {text_preview}")
        print(f"       Regex [{regex_status}]  NER [{ner_status}]  — {note}")

        # show what was actually found
        if result["regex_hits"]:
            for ph, orig in result["regex_hits"].items():
                print(f"         REGEX  {ph:20s}  ←  {orig}")
        if not skip_ner and result["ner_hits"]:
            for ph, orig in result["ner_hits"].items():
                print(f"         NER    {ph:20s}  ←  {orig}")

        if verbose:
            print(f"         OUT  → {textwrap.shorten(result['redacted'], 80, placeholder='…')}")

    # ── summary ───────────────────────────────────────────────────────────────
    print(f"\n{'═'*60}")
    print(f"  Results:  {passed} passed  |  {failed} failed  |  {skipped} skipped  (of {total})")
    print(f"{'═'*60}")

    if failures:
        print("\n  Failed cases:")
        for c in failures:
            print(f"    • {c['note']}")
            print(f"      \"{textwrap.shorten(c['text'], 60)}\"")
    else:
        print("\n  All assertions passed ✓")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Redactor edge-case test suite")
    parser.add_argument("--no-ner",   action="store_true", help="Skip NER layer (faster)")
    parser.add_argument("--verbose",  action="store_true", help="Print full redacted output")
    args = parser.parse_args()
    run(verbose=args.verbose, skip_ner=args.no_ner)