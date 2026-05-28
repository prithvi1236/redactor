# ClipRedact

ClipRedact is a local clipboard privacy utility that redacts sensitive data before you paste into external AI tools, and restores the originals after you get a response — entirely on your machine.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

## Why This Exists

Most sensitive data leaks don't happen through hacks. They happen through convenience — copying a log, a config snippet, or a work note into ChatGPT without checking what's in it.

API keys, client names, internal metrics, and credentials routinely end up in prompts sent to servers you don't control. ClipRedact intercepts that moment: press a hotkey before you paste, and only the redacted version leaves your clipboard. The model on the other end never sees the original.

No data is sent to any server. No cloud service is involved in redaction. The NER model runs locally on your CPU or GPU.

## How It Works

Redaction runs as a two-layer pipeline. Structural secrets are caught instantly by regex. Contextual entities like names and organisations are caught by a local NER model, but only when context signals they are sensitive — so public figures and well-known companies are left alone.

```text
┌─────────────────────┐
│  Clipboard Input    │
└─────────┬───────────┘
          │
          v
┌─────────────────────┐
│ Layer 1: Regex      │  API keys, JWTs, emails, phones, IPs,
│ (instant)           │  password key=value pairs, conn strings
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
└─────────┬───────────┘
          │
          v
┌─────────────────────┐
│ Restore Hotkey      │  Swap placeholders back to originals
└─────────────────────┘
```

## Redaction Examples

| Before (copied text) | After (clipboard content) |
|---|---|
| `Email me at sarah@acme.com and use key sk_live_1234567890abcdef.` | `Email me at [EMAIL_1] and use key [API_KEY_1].` |
| `our CEO Sarah Connor joined Acme Corp this quarter.` | `our CEO ⟪PERSON·a1b2⟫ joined ⟪ORG·3c4d⟫ this quarter.` |
| `postgres://admin:pass@db.com/prod` | `[CONN_STRING_1]` |
| `postgres://user@db.com/analytics` | `postgres://user@db.com/analytics` *(no credentials — unchanged)* |
| `Google released a new model yesterday.` | `Google released a new model yesterday.` *(public org — unchanged)* |
| `tell me about India` | `tell me about India` *(no trigger word — unchanged)* |

## Quickstart

Install dependencies and start the utility in three steps.

**1. Install Python 3.11 or newer.**

**2. Install dependencies:**

```bash
pip install pynput pyperclip plyer transformers torch
```

> On first run the NER model (`dslim/bert-base-NER`, ~400 MB) is downloaded automatically and cached locally. This only happens once.

**3. Start the redactor:**

```bash
python redactor.py
```

The app runs silently in the background. The terminal prints a redaction map each time the hotkey fires (placeholder → original, local only).

## Redact and Restore Flow

**Redacting before you paste:**
1. Copy text in any app (`Ctrl+C`).
2. Press the **redact hotkey** (`Ctrl+Shift+X`).
3. Paste the redacted version into your AI tool (`Ctrl+V`).

**Restoring after the model responds:**
1. Copy the AI response (`Ctrl+C`).
2. Press the **restore hotkey** (`Ctrl+Shift+Z`).
3. Paste the fully restored text back into your own tools (`Ctrl+V`).

Mappings are held in memory for the duration of the session (see `SESSION_TTL`). Restarting the process clears all mappings.

## Hotkey Reference

| Action | Platform | Default Hotkey |
|---|---|---|
| Redact | Windows / Linux | `Ctrl + Shift + X` |
| Redact | macOS | `Cmd + Shift + X` |
| Restore | Windows / Linux | `Ctrl + Shift + Z` |
| Restore | macOS | `Cmd + Shift + Z` |

macOS requires Accessibility permission in System Settings → Privacy & Security → Accessibility.

To change a hotkey, edit the `HOTKEY` or `HOTKEY_RESTORE` constants in `redactor.py`.

## Configuration

All tuneable constants are at the top of `redactor.py`.

| Constant | Default | Description |
|---|---|---|
| `HOTKEY` | `<ctrl>+<shift>+x` | Global redact shortcut |
| `HOTKEY_RESTORE` | `<ctrl>+<shift>+z` | Global restore shortcut |
| `SESSION_TTL` | `3600` | Seconds before a mapping expires. Mappings are in-memory only — they do not survive a process restart. |
| `NER_WINDOW_SIZE` | `5` | Words scanned before and after an entity for trigger words |
| `NER_MIN_CONFIDENCE` | `0.85` | Minimum NER confidence score to act on an entity |
| `NER_TRIGGER_WORDS` | *(see source)* | Context words that enable PERSON / ORG masking (e.g. `our`, `ceo`, `client`) |
| `NER_PUBLIC_ORG_ALLOWLIST` | *(see source)* | Organisations never masked regardless of context |
| `NER_TOKEN_HEX_BYTES` | `2` | Byte length of random suffix in NER placeholders |

## Running Tests

```bash
python test_redactor.py            # full suite — both layers
python test_redactor.py --no-ner   # regex only, no model needed
python test_redactor.py --verbose  # also prints redacted output per case
```

## Edge Cases

**Masked correctly:**
- `our CEO Sarah Connor` → masked (`our` is a trigger within 5 words of the entity)
- `John Doe, our CTO` → masked (trigger word after the entity — bidirectional window)
- Same entity appearing twice → same placeholder reused (deduplication)
- `postgres://admin:pass@db.com/prod` → masked (credentials present)

**Intentionally not masked:**
- `tell me about India` → not masked (no trigger word near entity)
- `Google released a model` → not masked (public org allowlist)
- `postgres://user@db.com/analytics` → not masked (no embedded credentials)
- `who is the CEO of Microsoft?` → not masked (public org, no possessive trigger)
- Hypothetical phrasing without a named entity (e.g. `what if someone earned $X`)

## Known Limitations

- Mappings are **in-memory only**. If the process is restarted between redacting and restoring, the mapping is gone and the restore hotkey will report no matching session entries.
- The NER model downloads approximately **400 MB** on first run. Subsequent runs use the local cache.
- NER warm-up takes **3 to 8 seconds** at startup (runs in a background thread, hotkey works throughout).
- Regex email detection can match **hypothetical email examples** in plain text (e.g. `user@domain.tld`).
- Non-text clipboard payloads (images, files) are ignored.
- NER detection is **English-only**. Names and organisations in other languages may not be caught.

## Roadmap

- Undo last redaction — single hotkey to revert clipboard to pre-redaction state.
- Mapping persistence via OS keychain (macOS Keychain, Windows Credential Manager) for cross-session restore.
- System tray mode for quieter background operation.
- Settings UI for categories, trigger words, and hotkey remapping.
- Packaged desktop builds (`.exe` / `.app`) with bundled model.

## Contributing

Contributions are welcome if they improve detection quality, reduce false positives, or enhance developer ergonomics.

1. Fork the repo and create a feature branch.
2. Add or update tests in `test_redactor.py`.
3. Run the full test suite before opening a pull request.
4. Include a clear problem statement and before/after behaviour in the PR description.

## License

MIT License.