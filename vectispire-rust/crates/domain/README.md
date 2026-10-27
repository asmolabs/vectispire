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
| `String.CASE_INSENSITIVE_ORDER` folds by the simple one-to-one mappings (`ß` stays, `İ` is `i`), code point by code point | `to_lowercase` uses the full mappings (`ß` → `ss`, `İ` → `i̇`) | `java::compare_ignore_case` |
| `equalsIgnoreCase` matches `İ` and `ı` to `i`, `K` (Kelvin) to `k`; `toUpperCase(ROOT)` makes `ſ` an `S` | `eq_ignore_ascii_case` does not | `cron` |

## The targets' rules (task 2.6)

`bounded_text::{required, optional, within}`, `repository_url::{identity, carries_credential, short_name,
display_name, is_masked_form_of}`, `repository_identity`, `image_reference`, `asset_tier`, `agent_labels`,
`list_window`, `git_host_allowlist` and `schedules::in_force` are held to `reference/targets/rules.json`
(`TargetRulesReferenceSetTest`, written before the port). `java_uri::Parsed` gained `raw_path`, which `identity`
reads as `URI.getRawPath`. `schedules` holds only what the listings need; the scheduler's `isDue` is task 2.7's.

## The SIEM's domain (task 4.2, first stage)

`siem` is `common.domain.siem`: the event catalogue (`SecurityEventType`, wire names, signature ids, CEF
severities and outcomes), `signalled_by` and the placement of every audit operation, `CefEvent` and its builder,
the RFC 5424 frame and octet counting (`syslog`), the endpoint an operator types (`endpoint`), the protocol, the
severity minimum and the triage signals, and the collector CA (`siem::collector_ca`) over `pinned_ca`, the X.509
reading of a pinned CA that the forge connections will share as Java shares it. It sits here, not in the export's crate, so that the modules raising an
event (issues, gate, the threat feed) build one without depending on the export — as the Java types sit in
`vectispire-common`. `TriageStatus` moved here from `cp-issues` with it (re-exported there), so that the gate and
the SOC's signals ask one `is_settled`.

Everything that leaves the system — the CEF line, the syslog header, the wire names, the refusals — is held to
`reference/siem/` (`SiemReferenceSetTest`). `cp-audit`'s `tests/siem_vocabulary.rs` holds the operations and the
placements to each other in both directions (Java's switch has no default; here the two lists live in different
crates), and every `Signal` written with a literal name in the workspace to a `SecurityEventType`.

Ported, but shaped for Rust: an issue's severity given to a type whose severity is fixed is refused by `build()`,
where Java throws at the call — either way no event exists. `SecurityEventRaised` and `SecurityEventRaisedApart`
are Spring events and are not here: the export's crate replaces them with a trait.

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
- **A syslog endpoint's IPv6 literal** is read by the standard library, plus the two JDK answers that matter: an
  IPv4-mapped address is not IPv6, a numeric scope is accepted. An interface-name scope (`%eth0`), which the JDK
  accepts only on a machine that has the interface, is refused everywhere; a group of more than four digits whose
  value fits (`01234::1`), which the JDK reads, is refused. Both refuse a spelling Java accepts — the safe side.
- **`TriageStatus::from_wire_name`** now trims and lowers as Java does (`String.trim`, `toLowerCase(ROOT)`);
  `cp-issues`' copy used `str::trim` and ASCII lowering, which disagreed on a leading control character and a
  trailing no-break space.
- **A pinned CA is read by `x509`, a DER reader of this crate's own** (no new dependency; `der`'s tags stop short of
  UniversalString, GraphicString and GeneralString, which BouncyCastle renders). It is stricter than BouncyCastle
  and never looser: a BER length (indefinite, or not in its shortest form), a constructed string, a tag number
  above 30, a time outside `YYMMDDHHMMSSZ`/`YYYYMMDDHHMMSSZ` or naming a date that does not exist (BouncyCastle's
  `SimpleDateFormat` rolls one over), an arc beyond 128 bits, a version tagged other than `[0]` — each a certificate
  Java pins and this refuses as unreadable. Two answers differ otherwise: a PEM object of a known non-certificate
  type is "something other than certificates" when its body is one well-formed DER element, where BouncyCastle
  first parses it as that type and says "not readable" if it is not one (both refuse); and a BMPString holding a
  lone surrogate renders it `?`, where Java keeps the unpaired unit.
