# vectispire-domain

What the agent and the control plane agree on as rules rather than code: the repository URL checks, the
address classes, failure kinds, the contract number — and, for the control plane (Phase 2, task 2.4), the
issue fingerprint and the target vocabulary, and Spring's cron parser. Each is a port of a Java class whose
answers are a contract; the Java side writes them into `reference/` and this crate's tests read them (see the
workspace [`README.md`](../../README.md), "The reference sets").

**Shared with the agent, so changes are additive only**: an item's behaviour or bytes do not change under
the agent's feet; its reference sets stay in `check.sh`.

## The Java behaviours reproduced, not improved

The fingerprint fails nowhere when it drifts — the backlog is resolved and recreated, triage lost — so every
Java behaviour under it is ported as Java has it, and held to `reference/fingerprints/` with no tolerance:

| Java | Rust's nearest | Here |
|---|---|---|
| `getBytes(UTF_8)` writes an unpaired surrogate as `?` | `String::from_utf16_lossy` writes U+FFFD | `java::from_utf16` |
| `String.strip` / `isBlank` ask `Character.isWhitespace`: not U+00A0, U+2007, U+202F, U+0085; yes U+001C–U+001F | `str::trim` the opposite on all seven | `java::strip`, `java::is_blank` |
| `String.trim` strips every char up to U+0020 | `str::trim` strips Unicode white space | `java::trim` |
| `toLowerCase(Locale.ROOT)` decides the capital sigma's final form with the word `BreakIterator` ("ΣΣ-ı" → "σσ-ı") | `to_lowercase` uses Unicode's case-ignorable rule ("σς-ı") | `java::to_lower_root` |
| `String.length()` counts UTF-16 units | `len()` bytes, `chars().count()` characters | `java::utf16_len`, `bounded_text` |
| `Integer.parseInt` reads any BMP decimal digit (`٣`, `５`), and its two overloads word refusals differently | `str::parse` reads ASCII only | `java::read_int`, `parse_int`, `parse_int_in` |
| Jackson's `asText(null)`: a number or boolean is its text, a container `""` | — | `java::as_text` |
| `equalsIgnoreCase` matches `İ` and `ı` to `i`, `K` (Kelvin) to `k`; `toUpperCase(ROOT)` makes `ſ` an `S` | `eq_ignore_ascii_case` does not | `cron` |

## Differences from Java, known

Decided 2026-10-17 by the 2.4 port; each is outside what any stored value or wire message can reach today.

- **A Rust `String` cannot hold an unpaired surrogate.** Java can, and hashes it as `?`; `java::from_utf16`
  makes that substitution where such a string enters, so fingerprints and keys agree byte for byte. What
  differs is only `bounded_text::clip` of a lone *high* surrogate exactly at the limit: Java drops it, here
  it is already a `?` and is kept — a display copy, one character, and a value PostgreSQL refuses anyway.
  `serde_json` refuses a lone surrogate escape outright where Jackson accepts it: **the ingestion (task 2.8)
  has to decide that reading**, or a result Java ingests is refused here.
- **The word rules behind the final sigma are a model** of the JDK's legacy word iterator (letters and
  digits alternating, single mid-word and mid-number marks, the danda, combining marks and format
  characters transparent, kana and ideographs apart). It agrees with Java on all 3,000 strings of
  `fingerprints/lowercase.json`; a script the corpus does not cover (Thai's dictionary breaks, astral
  digits) could still differ, and only for a tool name holding a capital sigma.
- **`as_text` of an integer beyond `u64`**: `serde_json` reads it as a double, Jackson as a `BigInteger`;
  only an SBOM id or parent of that size would notice.
- **`cron`, past year 999,999,999**: the search stops (`None`) where Java throws a `DateTimeException`.
