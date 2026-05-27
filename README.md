# ClipRedact

ClipRedact is a local clipboard privacy utility that redacts sensitive text before you paste it into external AI tools. **100% local processing: no secrets leaves your machine.**

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

## Why This Exists

ClipRedact helps you keep secrets and identifiable information out of prompts when sharing logs, snippets, or notes with ChatGPT, Claude, Gemini, and similar tools.

- Copy text from any app.
- Press a global hotkey.
- Paste a redacted version instead of the original.
- Review a local redaction map in your terminal (placeholder -> original).

## How It Works

The redaction pipeline uses two layers so structural secrets are masked instantly and contextual entities are masked only when likely sensitive.

```text
┌─────────────────────┐
│  Clipboard Input    │
└─────────┬───────────┘
          │
          v
┌─────────────────────┐
│ Layer 1: Regex      │  API keys, JWTs, emails, phones, IPs,
│ (instant)           │  password-like key=value, conn strings
└─────────┬───────────┘
          │
          v
┌─────────────────────┐
│ Layer 2: Local NER  │  PERSON / ORG with trigger-word gating
│ (dslim/bert-base)   │  + public-org allowlist
└─────────┬───────────┘
          │
          v
┌─────────────────────┐
│ Clipboard Output    │  Safe-to-paste redacted text
└─────────────────────┘
```

## Redaction Examples

The examples below show realistic clipboard text and what you get after pressing the hotkey.

| Before (copied text) | After (clipboard content) |
|---|---|
| `Email me at sarah@acme.com and use key sk_live_1234567890abcdef.` | `Email me at [EMAIL_1] and use key [API_KEY_1].` |
| `our CEO Sarah Connor joined Acme Corp this quarter.` | `our CEO ⟪PERSON·a1b2⟫ joined ⟪ORG·3c4d⟫ this quarter.` |
| `postgres://admin:pass@db.com/prod` | `[CONN_STRING_1]` |
| `postgres://user@db.com/analytics` | `postgres://user@db.com/analytics` (unchanged) |
| `Google released a new model yesterday.` | `Google released a new model yesterday.` (unchanged) |

## Quickstart

You can install and run ClipRedact in under five steps.

1. Install Python 3.11 or newer.
2. Install dependencies:

```bash
pip install pynput pyperclip plyer transformers torch
```

3. Start the redactor:

```bash
python redactor.py
```

4. Copy text in any app, press the hotkey, then paste.
5. Check your terminal for the local redaction map.

## Hotkey Reference

The global shortcut differs by platform, and macOS needs one additional permission.

| Platform | Default Hotkey | Notes |
|---|---|---|
| Windows / Linux | `Ctrl + Shift + X` | Works with `HOTKEY = "<ctrl>+<shift>+x"` |
| macOS | `Cmd + Shift + X` | Update `HOTKEY` to `"<cmd>+<shift>+x"` and grant Accessibility permission |

## Configuration

You can tune redaction behavior by editing constants in `redactor.py`.

- `HOTKEY`: global activation shortcut.
- `NER_WINDOW_SIZE`: number of words scanned before and after an entity for trigger words.
- `MIN_CONFIDENCE`: conceptual confidence threshold for entity masking (implemented as `NER_MIN_CONFIDENCE` in code).
- `NER_TRIGGER_WORDS`: contextual words that enable PERSON/ORG masking.
- `PUBLIC_ORG_ALLOWLIST`: organization names never masked (always treated as public).

Additional useful knobs currently available:

- `NER_TOKEN_HEX_BYTES`: random suffix length for NER placeholders.
- `NER_LABEL_MAP`: model label mapping (`PER` -> `PERSON`, `ORG` -> `ORG`).

## Running Tests

The test suite validates layer behavior, edge cases, and expected masking decisions.

```bash
python test_redactor.py
python test_redactor.py --no-ner
python test_redactor.py --verbose
```

## Edge Cases

ClipRedact intentionally balances privacy with usability by masking contextually sensitive entities and avoiding over-redaction where possible.

Handled as expected:

- `tell me about India` -> not masked (no trigger word near entity).
- `Google released a model` -> not masked (public org allowlist).
- `postgres://user@db.com/analytics` -> not masked (no embedded credentials).
- `postgres://admin:pass@db.com/prod` -> masked (credentials present).
- Same entity repeated -> same placeholder reused (deduplication).
- `John Doe, our CTO` -> masked (trigger word can appear after entity).
- NER model warm-up runs in a background thread so hotkey stays responsive.

Intentionally not masked:

- Hypothetical phrasing without trigger context (for example, "what if someone earned $X").
- Image/screenshot clipboard content (text-only pipeline).

## Known Limitations

Current constraints are mostly startup and scope trade-offs.

- First NER load may take ~3 to 8 seconds (background warm-up).
- Regex email detection can match hypothetical examples in plain text.
- Non-text clipboard payloads are ignored.

## Roadmap

Next planned improvements focus on usability and workflow completeness.

- System tray mode for quieter background operation.
- Reverse substitution to restore originals in model responses.
- Settings UI for categories, trigger words, and hotkey remapping.
- Packaged desktop builds (`.exe` / `.app`) for easier installation.

## Contributing

Contributions are welcome if they improve detection quality, reduce false positives, or enhance developer ergonomics.

1. Fork the repo and create a feature branch.
2. Add or update tests in `test_redactor.py`.
3. Run the test commands above.
4. Open a pull request with a clear problem statement and before/after behavior.

## License

This project is released under the MIT License.
