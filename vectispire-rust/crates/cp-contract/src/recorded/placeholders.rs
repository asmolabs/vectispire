//! The recorder's placeholders, read back (`Placeholders.java`, `core/golden/README.md` § Placeholders).
//!
//! A recorded value is a **template**: literal text with `«…»` where the recorder replaced something that changes
//! from run to run. This module does the two things a replay needs with one:
//!
//! - **substitute** — a seed row or a request is made concrete: `«t_repository#1»` becomes the id this replay gave
//!   the first repository, `«secret:2»` a credential minted here (or one the server minted and an earlier answer
//!   carried), `«datetime»` the clock's;
//! - **match** — an answer or a row the Rust server produced is held to the template: every literal byte must be
//!   there, and each placeholder must cover a value **of the shape the recorder's rule replaces**, consistently.
//!
//! **Why matching, and not normalising the Rust side and comparing.** Rendering Rust's answer with the recorder's
//! rules would number its UUIDs and secrets in the order they are first rendered, which is the order the bytes come
//! in, not behaviour; and it would hide a value of the wrong kind under a placeholder of another (a UUID where Java
//! wrote an id renders to *some* placeholder too). Matching is narrower: an ordinal placeholder (`«uuid:3»`,
//! `«secret:1»`, `«sha256:2»`, `«n:4»`, `«port:1»`, `«pem:…:1»`) binds to one value per test, the same ordinal to
//! the same value everywhere, two ordinals never to one value — exactly what the recorder's numbering says; an
//! identity is not bound at all, it is computed (`start + rank - 1`) and must be that number; a hash of a secret must
//! be that secret's hash; a password hash must verify against the password it names; a date must be in the
//! recorder's window. What remains lenient is what the recorder itself threw away — the instant inside the window,
//! the ciphertext of a sealed value, the digits of a one-time code — and nothing else.

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use regex::Regex;
use time::{Date, Duration, Month, OffsetDateTime};

use crate::json::Json;

/// `ApiTestBase`'s passphrase: a fixture in the Java source, never a secret (`Placeholders.FIXTURE_PASSWORD`).
pub const FIXTURE_PASSWORD: &str = "correct horse battery staple";

/// What one `«…»` stands for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Placeholder {
    /// `«t_repository#3»`: the third id of the table in the test; `rank` is `None` for `#prior`.
    Id {
        table: String,
        rank: Option<i64>,
    },
    /// `«secret:N»`: a credential the test presented or the server minted.
    Secret(u32),
    /// `«secret:N:prefix»`: an API key's stored prefix, its first twelve characters.
    SecretPrefix(u32),
    /// `«sha256(secret:N)»`: the SHA-256 hex of a credential — a session's `token_hash`.
    SecretHash(u32),
    /// `«password-hash(…)»`: an Argon2 or bcrypt hash, and which password it holds.
    PasswordHash(PasswordOf),
    /// `«sealed»`: a `SecretCipher` value; its nonce is random.
    Sealed,
    /// `«sha256:N»`: a digest no secret accounts for.
    Digest(u32),
    /// `«sha256-prefix:N»`: a digest cut short in a sentence, numbered with the digests.
    DigestPrefix(u32),
    /// `«port:N»`: a loopback port.
    Port(u32),
    /// `«uuid:N»`.
    Uuid(u32),
    /// `«date»`, `«datetime»` (no zone), `«instant»` (`Z` or an offset), within the window.
    Date,
    DateTime,
    Instant,
    /// `«http-date»`: RFC 1123, within the window.
    HttpDate,
    /// `«stamp»`: `20261016T101500Z`, `20261016-1015`, within the window.
    Stamp,
    /// `«n:N»`: twelve to nineteen digits — a `nanoTime` or `currentTimeMillis` suffix.
    Long(u32),
    /// `«one-time-code»`, `«window»` (a rate window's number), `«clock-step»` (a TOTP step).
    OneTimeCode,
    Window,
    ClockStep,
    /// `«pem:private-key:1»`: a whole PEM block — a private key; a certificate or a public key is recorded literally.
    Pem {
        label: String,
        ordinal: u32,
    },
}

/// Whose password a hash holds, as far as the recorder could tell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordOf {
    Fixture,
    Secret(u32),
    Unknown,
}

/// A piece of a template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    Literal(String),
    Placeholder(Placeholder),
}

fn pattern(text: &str) -> Regex {
    // Literals of this file: one that does not compile is a defect the first test of the crate shows.
    Regex::new(text).unwrap_or_else(|error| panic!("a placeholder pattern does not compile: {error}"))
}

struct Grammar {
    id: Regex,
    ordinal: Regex,
    password: Regex,
    pem: Regex,
}

static GRAMMAR: LazyLock<Grammar> = LazyLock::new(|| Grammar {
    id: pattern(r"^(t_[a-z0-9_]+)#([0-9]+|prior)$"),
    ordinal: pattern(r"^(secret|sha256|sha256-prefix|port|uuid|n):([0-9]+)$"),
    password: pattern(r"^password-hash\((.*)\)$"),
    pem: pattern(r"^pem:([a-z0-9-]+):([0-9]+)$"),
});

fn ordinal_of(text: &str) -> Option<u32> {
    text.parse().ok()
}

/// What the inside of `«…»` names, or `None` for text the recorder did not write as a placeholder — a blob's
/// `«bytes:…»` and `«clob:unreadable»` are row values (`RowSnapshots`), compared as they are written.
#[must_use]
pub fn placeholder(inner: &str) -> Option<Placeholder> {
    let fixed = match inner {
        "sealed" => Some(Placeholder::Sealed),
        "date" => Some(Placeholder::Date),
        "datetime" => Some(Placeholder::DateTime),
        "instant" => Some(Placeholder::Instant),
        "http-date" => Some(Placeholder::HttpDate),
        "stamp" => Some(Placeholder::Stamp),
        "one-time-code" => Some(Placeholder::OneTimeCode),
        "window" => Some(Placeholder::Window),
        "clock-step" => Some(Placeholder::ClockStep),
        _ => None,
    };
    if fixed.is_some() {
        return fixed;
    }
    let grammar = &*GRAMMAR;
    if let Some(found) = grammar.id.captures(inner) {
        let table = found.get(1)?.as_str().to_owned();
        let rank = match found.get(2)?.as_str() {
            "prior" => None,
            digits => Some(digits.parse().ok()?),
        };
        return Some(Placeholder::Id { table, rank });
    }
    if let Some(found) = grammar.ordinal.captures(inner) {
        let ordinal = ordinal_of(found.get(2)?.as_str())?;
        return Some(match found.get(1)?.as_str() {
            "secret" => Placeholder::Secret(ordinal),
            "sha256" => Placeholder::Digest(ordinal),
            "sha256-prefix" => Placeholder::DigestPrefix(ordinal),
            "port" => Placeholder::Port(ordinal),
            "uuid" => Placeholder::Uuid(ordinal),
            _ => Placeholder::Long(ordinal),
        });
    }
    if let Some(rest) = inner.strip_prefix("secret:").and_then(|rest| rest.strip_suffix(":prefix")) {
        return ordinal_of(rest).map(Placeholder::SecretPrefix);
    }
    if let Some(rest) = inner.strip_prefix("sha256(secret:").and_then(|rest| rest.strip_suffix(')')) {
        return ordinal_of(rest).map(Placeholder::SecretHash);
    }
    if let Some(found) = grammar.password.captures(inner) {
        let whose = found.get(1)?.as_str();
        return Some(Placeholder::PasswordHash(match whose {
            FIXTURE_PASSWORD => PasswordOf::Fixture,
            "?" => PasswordOf::Unknown,
            other => PasswordOf::Secret(ordinal_of(other.strip_prefix("secret:")?)?),
        }));
    }
    if let Some(found) = grammar.pem.captures(inner) {
        return Some(Placeholder::Pem {
            label: found.get(1)?.as_str().to_owned(),
            ordinal: ordinal_of(found.get(2)?.as_str())?,
        });
    }
    None
}

/// A template, cut into literals and placeholders.
#[must_use]
pub fn segments(text: &str) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    let push_literal = |out: &mut Vec<Segment>, literal: &str| {
        if literal.is_empty() {
            return;
        }
        if let Some(Segment::Literal(previous)) = out.last_mut() {
            previous.push_str(literal);
        } else {
            out.push(Segment::Literal(literal.to_owned()));
        }
    };
    let mut pieces = text.split('«');
    if let Some(first) = pieces.next() {
        push_literal(&mut out, first);
    }
    for piece in pieces {
        match piece.split_once('»') {
            Some((inner, rest)) => match placeholder(inner) {
                Some(found) => {
                    out.push(Segment::Placeholder(found));
                    push_literal(&mut out, rest);
                }
                None => push_literal(&mut out, &format!("«{inner}»{rest}")),
            },
            None => push_literal(&mut out, &format!("«{piece}")),
        }
    }
    out
}

/// What a replay cannot make concrete: the value the recorder hid is not one the replay can choose.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Unseedable(pub String);

/// The credentials a replay mints and checks, with the control plane's own code — implemented by the caller,
/// because the contract crate depends on no module (`edges.toml`) and the hashing is `cp-access`'s.
pub trait Minting: Send + Sync {
    /// A session token as `AuthService` issues one.
    fn session_token(&self) -> String;
    /// A full API key as `ApiKeys.generate()` makes one.
    fn api_key(&self) -> String;
    /// The SHA-256 hex a session's `token_hash` stores.
    fn sha256_hex(&self, text: &str) -> String;
    /// The stored hash of a password or an API key.
    fn password_hash(&self, plain: &str) -> String;
    /// Whether `hash` holds `plain`.
    fn password_verifies(&self, plain: &str, hash: &str) -> bool;
}

/// How a secret the replay must mint itself is minted: an API key when the test ever shows its stored prefix,
/// a session-shaped token otherwise (a session token, an agent key, a password — any random value will do for
/// those, since only its hash and its echo are ever compared).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretKind {
    Token,
    ApiKey,
}

/// One ordinal family: an ordinal names one value, and a value one ordinal.
#[derive(Clone, Debug, Default)]
struct Ordinals {
    by_ordinal: BTreeMap<u32, String>,
    by_value: HashMap<String, u32>,
}

impl Ordinals {
    fn get(&self, ordinal: u32) -> Option<&str> {
        self.by_ordinal.get(&ordinal).map(String::as_str)
    }

    /// Whether `value` may be `ordinal`: not bound to another value, and the value not another ordinal's.
    fn admits(&self, ordinal: u32, value: &str) -> Result<(), String> {
        if let Some(bound) = self.by_ordinal.get(&ordinal)
            && bound != value
        {
            return Err(format!("is {value:?}, and the same placeholder was {bound:?} earlier in the test"));
        }
        if let Some(other) = self.by_value.get(value)
            && *other != ordinal
        {
            return Err(format!("is {value:?}, which an earlier value of the test numbered {other} was already"));
        }
        Ok(())
    }

    fn bind(&mut self, ordinal: u32, value: &str) {
        self.by_ordinal.insert(ordinal, value.to_owned());
        self.by_value.insert(value.to_owned(), ordinal);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Family {
    Secret,
    Digest,
    Port,
    Uuid,
    Long,
    Pem,
}

/// A check owed to a secret not known yet: its hash or prefix was seen before the secret itself.
#[derive(Clone, Debug)]
enum Owed {
    Hash(u32, String),
    Prefix(u32, String),
    Password(u32, String),
}

/// Where a concrete clock value goes: a row stores `2026-10-18 10:15:30.000001`, the wire carries ISO-8601.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    Row,
    Wire,
}

/// One test's placeholders and what each was found or made to be. Cloned to try a match that may be abandoned (a
/// row of a table keyed by a UUID, matched against each candidate in turn).
#[derive(Clone)]
pub struct Bindings<'m> {
    /// Each table's first id in the test: rank 1. A rank is `id - start + 1`, the recorder's own reckoning.
    starts: BTreeMap<String, i64>,
    families: BTreeMap<Family, Ordinals>,
    kinds: BTreeMap<u32, SecretKind>,
    owed: Vec<Owed>,
    /// Sessions a seed wrote whose token the recording never tied to its hash (see `concrete_one`).
    orphans: Vec<(u32, String)>,
    /// Differences found when a secret became known and a check owed to it failed.
    violations: Vec<String>,
    minting: &'m dyn Minting,
    verified: HashMap<(String, String), bool>,
    fixture_hash: Option<String>,
    today: Date,
    clock: OffsetDateTime,
    next_long: u64,
}

impl std::fmt::Debug for Bindings<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("Bindings").field("starts", &self.starts).field("violations", &self.violations).finish()
    }
}

/// `Placeholders.inWindow`: three years back, eleven ahead, the day clamped to the month as `LocalDate.of` does.
#[must_use]
pub fn in_window(today: Date, year: i32, month: u8, day: u8) -> bool {
    let Ok(month) = Month::try_from(month) else {
        return false;
    };
    if !(1..=31).contains(&day) {
        return false;
    }
    let Ok(date) = Date::from_calendar_date(year, month, day.min(month.length(year))) else {
        return false;
    };
    match (shift_years(today, -3), shift_years(today, 11)) {
        (Some(from), Some(to)) => date >= from && date <= to,
        _ => false,
    }
}

/// `LocalDate.plusYears`: the 29th of February becomes the 28th in a common year.
fn shift_years(date: Date, years: i32) -> Option<Date> {
    let year = date.year().checked_add(years)?;
    Date::from_calendar_date(year, date.month(), date.day().min(date.month().length(year))).ok()
}

fn digits_of(text: &str) -> Option<(i32, u8, u8)> {
    let mut chars = text.chars();
    let year: String = chars.by_ref().take(4).collect();
    let rest: String = chars.collect();
    let rest = rest.strip_prefix('-').unwrap_or(&rest);
    let mut rest_chars = rest.chars();
    let month: String = rest_chars.by_ref().take(2).collect();
    let after: String = rest_chars.collect();
    let after = after.strip_prefix('-').unwrap_or(&after);
    let day: String = after.chars().take(2).collect();
    Some((year.parse().ok()?, month.parse().ok()?, day.parse().ok()?))
}

/// The shape each rule of the recorder replaces — the regular expressions of `Placeholders.java`, anchored by the
/// template around them. Never wider than the rule: a value of another shape is a difference.
fn shape(placeholder: &Placeholder, sole_in_hash_field: bool) -> &'static str {
    match placeholder {
        Placeholder::Id { .. } => r"[1-9][0-9]{8}",
        // `registerSecret` takes anything of six characters or more.
        Placeholder::Secret(_) => r"[^\s]{6,}?",
        Placeholder::SecretPrefix(_) => r"zsk_[A-Za-z0-9_-]{8}",
        Placeholder::SecretHash(_) => r"[0-9a-fA-F]{64}",
        Placeholder::PasswordHash(_) => r#"\$argon2(?:id|i|d)\$[^\s"]+|\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}"#,
        Placeholder::Sealed => r"v2:[A-Za-z0-9+/_-]+=*",
        // A field named like a hash holding 32 to 128 hex digits and nothing else is a digest too.
        Placeholder::Digest(_) if sole_in_hash_field => r"[0-9a-fA-F]{32,128}",
        Placeholder::Digest(_) => r"[0-9a-fA-F]{64}",
        Placeholder::DigestPrefix(_) => r"[0-9a-fA-F]{8,63}",
        Placeholder::Port(_) => r"[0-9]{2,5}",
        Placeholder::Uuid(_) => r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        Placeholder::Date => r"[0-9]{4}-[0-9]{2}-[0-9]{2}",
        Placeholder::DateTime => r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:[.,][0-9]{1,9})?)?",
        Placeholder::Instant => {
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:[.,][0-9]{1,9})?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})"
        }
        Placeholder::HttpDate => {
            r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT"
        }
        Placeholder::Stamp => r"[0-9]{8}(?:T[0-9]{4,6}Z?|-[0-9]{4,6})",
        Placeholder::Long(_) => r"[0-9]{12,19}",
        Placeholder::OneTimeCode => r"[0-9]{6,8}|[a-z0-9]{4}-[a-z0-9]{4}",
        Placeholder::Window => r"[0-9]+",
        Placeholder::ClockStep => r"-?[0-9]+",
        Placeholder::Pem { .. } => r"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----",
    }
}

const ONE_TIME_CODE_FIELDS: [&str; 5] = ["code", "totp", "totpcode", "mfacode", "otp"];

impl<'m> Bindings<'m> {
    /// A test's bindings: `starts` is each table's first id in the test, `kinds` how each secret the replay may
    /// have to mint is minted (see [`secret_kinds`]).
    #[must_use]
    pub fn new(
        starts: BTreeMap<String, i64>,
        kinds: BTreeMap<u32, SecretKind>,
        minting: &'m dyn Minting,
        now: OffsetDateTime,
    ) -> Bindings<'m> {
        Bindings {
            starts,
            families: BTreeMap::new(),
            kinds,
            owed: Vec::new(),
            orphans: Vec::new(),
            violations: Vec::new(),
            minting,
            verified: HashMap::new(),
            fixture_hash: None,
            today: now.date(),
            clock: now,
            next_long: 100_000_000_000_000,
        }
    }

    /// The id of `table`'s row of rank `rank` in this test.
    #[must_use]
    pub fn id_of(&self, table: &str, rank: i64) -> Option<i64> {
        self.starts.get(table)?.checked_add(rank)?.checked_sub(1)
    }

    /// The differences found since the last call, when a secret became known and a check owed to it failed.
    pub fn take_violations(&mut self) -> Vec<String> {
        std::mem::take(&mut self.violations)
    }

    fn family(&mut self, family: Family) -> &mut Ordinals {
        self.families.entry(family).or_default()
    }

    fn bound(&self, family: Family, ordinal: u32) -> Option<&str> {
        self.families.get(&family)?.get(ordinal)
    }

    fn verifies(&mut self, plain: &str, hash: &str) -> bool {
        let key = (plain.to_owned(), hash.to_owned());
        if let Some(known) = self.verified.get(&key) {
            return *known;
        }
        let answer = self.minting.password_verifies(plain, hash);
        self.verified.insert(key, answer);
        answer
    }

    /// Binds a secret, and runs the checks owed to it.
    fn bind_secret(&mut self, ordinal: u32, value: &str) {
        self.family(Family::Secret).bind(ordinal, value);
        let owed = std::mem::take(&mut self.owed);
        for check in owed {
            match check {
                Owed::Hash(n, hash) if n == ordinal => {
                    let wanted = self.minting.sha256_hex(value);
                    if !hash.eq_ignore_ascii_case(&wanted) {
                        self.violations.push(format!("«sha256(secret:{n})» was {hash:?}, not the secret's hash"));
                    }
                }
                Owed::Prefix(n, prefix) if n == ordinal => {
                    if !value.starts_with(prefix.as_str()) {
                        self.violations.push(format!("«secret:{n}:prefix» was {prefix:?}, not the key's prefix"));
                    }
                }
                Owed::Password(n, hash) if n == ordinal => {
                    if !self.verifies(value, &hash) {
                        self.violations.push(format!("«password-hash(secret:{n})» does not verify against it"));
                    }
                }
                other => self.owed.push(other),
            }
        }
    }

    /// The secret `ordinal`, minted now when nobody has shown it yet.
    fn secret(&mut self, ordinal: u32) -> String {
        if let Some(bound) = self.bound(Family::Secret, ordinal) {
            return bound.to_owned();
        }
        let minted = match self.kinds.get(&ordinal) {
            Some(SecretKind::ApiKey) => self.minting.api_key(),
            Some(SecretKind::Token) | None => self.minting.session_token(),
        };
        self.bind_secret(ordinal, &minted);
        minted
    }

    /// A clock value: the wall clock, and never before the previous one plus a microsecond — rows a test seeded one
    /// after the other keep that order when a listing sorts them by time, and a row played in Java's place lands
    /// after the rows the server wrote before it (the audit chain links an entry to the newest one).
    fn tick(&mut self) -> OffsetDateTime {
        let next = self.clock.saturating_add(Duration::microseconds(1));
        let now = OffsetDateTime::now_utc();
        self.clock = if now > next { now } else { next };
        self.clock
    }

    fn fresh_long(&mut self) -> String {
        loop {
            self.next_long = self.next_long.saturating_add(1);
            let candidate = self.next_long.to_string();
            if !self.families.get(&Family::Long).is_some_and(|longs| longs.by_value.contains_key(&candidate)) {
                return candidate;
            }
        }
    }

    // ── Substitution ─────────────────────────────────────────────────────────────────────────────────────────

    /// `template` made concrete. `field` is the column or member it sits in: a clock value under a name that says
    /// it expires is put a day ahead, since a session seeded as expiring "now" would refuse the request it is for.
    pub fn concrete(&mut self, template: &str, field: &str, context: Context) -> Result<String, Unseedable> {
        let mut out = String::new();
        for segment in segments(template) {
            match segment {
                Segment::Literal(text) => out.push_str(&text),
                Segment::Placeholder(found) => out.push_str(&self.concrete_one(&found, field, context)?),
            }
        }
        Ok(out)
    }

    fn concrete_one(&mut self, placeholder: &Placeholder, field: &str, context: Context) -> Result<String, Unseedable> {
        let hidden = |what: &str| {
            Err(Unseedable(format!("{what} in `{field}`: the recording hid a value the replay cannot choose")))
        };
        match placeholder {
            Placeholder::Id { table, rank: Some(rank) } => self
                .id_of(table, *rank)
                .map(|id| id.to_string())
                .ok_or_else(|| Unseedable(format!("«{table}#{rank}»: no identity range for {table}"))),
            Placeholder::Id { table, rank: None } => hidden(&format!("«{table}#prior»")),
            // A bearer the test presents, unseen until now: the session it opens was seeded in an earlier file of the
            // test, rendered before the recorder had met the token (it collects a file's credentials before rendering
            // that file, not the files before it), so its hash shows as a bare `«sha256:K»`. That seeded session is
            // the one the token opens — the oldest one nobody has claimed. Narrow on purpose: only an `Authorization`
            // header takes one, and a wrong pick is a refusal or another account's answer, a difference, never a
            // green.
            Placeholder::Secret(n)
                if field == "authorization" && self.bound(Family::Secret, *n).is_none() && !self.orphans.is_empty() =>
            {
                let (_, token) = self.orphans.remove(0);
                self.bind_secret(*n, &token);
                Ok(token)
            }
            Placeholder::Secret(n) => Ok(self.secret(*n)),
            Placeholder::SecretPrefix(n) => Ok(self.secret(*n).chars().take(12).collect()),
            Placeholder::SecretHash(n) => {
                let secret = self.secret(*n);
                Ok(self.minting.sha256_hex(&secret))
            }
            Placeholder::PasswordHash(PasswordOf::Fixture) => {
                if let Some(hash) = &self.fixture_hash {
                    return Ok(hash.clone());
                }
                // Argon2 is slow on purpose: one hash of the fixture serves every account of the replay.
                let hash = self.minting.password_hash(FIXTURE_PASSWORD);
                self.fixture_hash = Some(hash.clone());
                Ok(hash)
            }
            Placeholder::PasswordHash(PasswordOf::Secret(n)) => {
                let secret = self.secret(*n);
                Ok(self.minting.password_hash(&secret))
            }
            // A password nobody in the test knows: the hash of one nobody will ever know does the same.
            Placeholder::PasswordHash(PasswordOf::Unknown) => {
                let nobody = self.minting.session_token();
                Ok(self.minting.password_hash(&nobody))
            }
            // A ciphertext nobody can open: a served route that decrypts it fails and differs from Java, which is a
            // difference shown, never one hidden; a route that only carries it (a listing, a deletion) is unaffected.
            Placeholder::Sealed => Ok(format!("v2:{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())),
            Placeholder::Digest(n) => {
                if let Some(bound) = self.bound(Family::Digest, *n) {
                    return Ok(bound.to_owned());
                }
                if field == "token_hash" {
                    // A session whose token the recording does not name yet: the hash of one minted now, kept for
                    // the bearer that will present it.
                    let token = self.minting.session_token();
                    let hash = self.minting.sha256_hex(&token);
                    self.family(Family::Digest).bind(*n, &hash);
                    self.orphans.push((*n, token));
                    return Ok(hash);
                }
                let fresh = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
                self.family(Family::Digest).bind(*n, &fresh);
                Ok(fresh)
            }
            Placeholder::DigestPrefix(n) => {
                if let Some(bound) = self.bound(Family::Digest, *n) {
                    return Ok(bound.to_owned());
                }
                // The shortest prefix the recorder names, not a typical one: the recording does not keep the length,
                // and a prefix may be the one a column cut short — `AuditLogService` truncates a description to 255,
                // so a checklist's "rule sha256 …" ending a long sentence was stored with eight digits, and twelve
                // made the played row outgrow the column. Never longer than Java's, it always fits where Java's did.
                let fresh: String = uuid::Uuid::new_v4().simple().to_string().chars().take(8).collect();
                self.family(Family::Digest).bind(*n, &fresh);
                Ok(fresh)
            }
            Placeholder::Uuid(n) => {
                if let Some(bound) = self.bound(Family::Uuid, *n) {
                    return Ok(bound.to_owned());
                }
                let fresh = uuid::Uuid::new_v4().to_string();
                self.family(Family::Uuid).bind(*n, &fresh);
                Ok(fresh)
            }
            Placeholder::Long(n) => {
                if let Some(bound) = self.bound(Family::Long, *n) {
                    return Ok(bound.to_owned());
                }
                let fresh = self.fresh_long();
                self.family(Family::Long).bind(*n, &fresh);
                Ok(fresh)
            }
            Placeholder::Date => Ok(self.tick().date().to_string()),
            Placeholder::DateTime | Placeholder::Instant => {
                let lower = field.to_ascii_lowercase();
                let mut at = self.tick();
                if lower.contains("expire") || lower.contains("until") {
                    at = at.saturating_add(Duration::days(1));
                }
                Ok(clock_text(at, context, matches!(placeholder, Placeholder::Instant)))
            }
            // A stub server's port the test named in a sentence: any port is as good, one per ordinal.
            Placeholder::Port(n) => {
                if let Some(bound) = self.bound(Family::Port, *n) {
                    return Ok(bound.to_owned());
                }
                let fresh = 40_000_u32.saturating_add(*n).to_string();
                self.family(Family::Port).bind(*n, &fresh);
                Ok(fresh)
            }
            Placeholder::HttpDate => hidden("«http-date»"),
            Placeholder::Stamp => hidden("«stamp»"),
            Placeholder::OneTimeCode => hidden("«one-time-code»"),
            // In a row played in Java's place (a webhook's hit in `t_rate_window`), the epoch's window: one that ended
            // long ago, so a served route counting the same subject starts a window of its own instead of finding
            // Java's hit — a count off by the seeded hits, which differs, never one that agrees by luck. A request
            // naming a window has to name the live one, which the recorder hid.
            Placeholder::Window if context == Context::Row => Ok("0".to_owned()),
            Placeholder::Window => hidden("«window»"),
            Placeholder::ClockStep => hidden("«clock-step»"),
            // In a row played in Java's place (a forge connection's CA, a stored key), a block of the same label
            // that no parser would accept: a served route that reads it differs from Java, which shows. In a request
            // the server must accept the key it is sent, and the recorder hid it: not replayable.
            Placeholder::Pem { label, ordinal } if context == Context::Row => {
                if let Some(bound) = self.bound(Family::Pem, *ordinal) {
                    return Ok(bound.to_owned());
                }
                let upper = label.to_ascii_uppercase().replace('-', " ");
                let fresh =
                    format!("-----BEGIN {upper}-----\n{}\n-----END {upper}-----", uuid::Uuid::new_v4().simple());
                self.family(Family::Pem).bind(*ordinal, &fresh);
                Ok(fresh)
            }
            Placeholder::Pem { label, ordinal } => hidden(&format!("«pem:{label}:{ordinal}»")),
        }
    }

    // ── Matching ─────────────────────────────────────────────────────────────────────────────────────────────

    /// Holds `actual` to `template`: `Ok` binds what the placeholders covered, `Err` says why it differs and binds
    /// nothing. `field` is the member or column the text sits in, lower-cased by the caller or not.
    pub fn match_text(&mut self, template: &str, actual: &str, field: &str) -> Result<(), String> {
        let parts = segments(template);
        if !parts.iter().any(|part| matches!(part, Segment::Placeholder(_))) {
            return if template == actual { Ok(()) } else { Err(format!("{actual:?}, recorded {template:?}")) };
        }
        let field = field.to_ascii_lowercase();
        let sole = parts.len() == 1;
        let mut expression = String::from("^(?:");
        let mut placeholders = Vec::new();
        for part in &parts {
            match part {
                Segment::Literal(text) => expression.push_str(&regex::escape(text)),
                Segment::Placeholder(found) => {
                    expression.push('(');
                    expression.push_str(
                        &self.pinned(found).unwrap_or_else(|| shape(found, sole && field.contains("hash")).to_owned()),
                    );
                    expression.push(')');
                    placeholders.push(found.clone());
                }
            }
        }
        expression.push_str(")$");
        let compiled = Regex::new(&expression).map_err(|error| format!("the template {template:?}: {error}"))?;
        let Some(captures) = compiled.captures(actual) else {
            return Err(format!("{actual:?} does not have the recorded shape {template:?}"));
        };
        // Checked against the bindings and among themselves before anything is bound: a value that fails half
        // way binds nothing.
        let mut proposed: Vec<(Family, u32, String)> = Vec::new();
        let mut secrets: Vec<(u32, String)> = Vec::new();
        let mut owed: Vec<Owed> = Vec::new();
        for (index, found) in placeholders.iter().enumerate() {
            let text = captures.get(index.saturating_add(1)).map_or("", |group| group.as_str());
            self.accept(found, text, &field, &mut proposed, &mut secrets, &mut owed)
                .map_err(|why| format!("{actual:?} against {template:?}: {} {why}", describe(found)))?;
        }
        for (family, ordinal, value) in proposed {
            self.family(family).bind(ordinal, &value);
        }
        for (ordinal, value) in secrets {
            self.bind_secret(ordinal, &value);
        }
        self.owed.extend(owed);
        Ok(())
    }

    /// The exact text a placeholder must be, when it is already decided.
    fn pinned(&self, placeholder: &Placeholder) -> Option<String> {
        let exact = match placeholder {
            Placeholder::Id { table, rank: Some(rank) } => self.id_of(table, *rank)?.to_string(),
            Placeholder::Secret(n) => self.bound(Family::Secret, *n)?.to_owned(),
            Placeholder::SecretPrefix(n) => self.bound(Family::Secret, *n)?.chars().take(12).collect(),
            Placeholder::SecretHash(n) => self.minting.sha256_hex(self.bound(Family::Secret, *n)?),
            _ => return None,
        };
        // A hex digest may come in either case; everything else is exact.
        Some(if matches!(placeholder, Placeholder::SecretHash(_)) {
            format!("(?i:{})", regex::escape(&exact))
        } else {
            regex::escape(&exact)
        })
    }

    fn accept(
        &mut self,
        placeholder: &Placeholder,
        text: &str,
        field: &str,
        proposed: &mut Vec<(Family, u32, String)>,
        secrets: &mut Vec<(u32, String)>,
        owed: &mut Vec<Owed>,
    ) -> Result<(), String> {
        let ordinal = |family: Family, n: u32, value: String, proposed: &mut Vec<(Family, u32, String)>| {
            if let Some(ordinals) = self.families.get(&family) {
                ordinals.admits(n, &value)?;
            }
            for (other_family, other_n, other_value) in proposed.iter() {
                if *other_family == family && ((*other_n == n) != (*other_value == value)) {
                    return Err(format!("is {value:?}, inconsistent with another placeholder of the same value"));
                }
            }
            proposed.push((family, n, value));
            Ok(())
        };
        match placeholder {
            // Pinned in the expression: the capture is already the id the rank computes.
            Placeholder::Id { rank: Some(_), .. } => Ok(()),
            Placeholder::Id { table, rank: None } => {
                let start = self.starts.get(table).copied().ok_or_else(|| format!("{table} has no identity range"))?;
                let value: i64 = text.parse().map_err(|_| format!("{text:?} is not an id"))?;
                let base = start.checked_sub(1).unwrap_or(start);
                if value >= base.checked_sub(base.rem_euclid(1_000_000)).unwrap_or(base) && value < start {
                    Ok(())
                } else {
                    Err(format!("{value} is not an id created before the test"))
                }
            }
            Placeholder::Secret(n) => {
                if self.bound(Family::Secret, *n).is_some() {
                    return Ok(());
                }
                let secrets_bound = self.families.get(&Family::Secret);
                if let Some(other) = secrets_bound.and_then(|known| known.by_value.get(text)) {
                    return Err(format!("is the secret numbered {other}"));
                }
                if secrets.iter().any(|(other, value)| (*other == *n) != (value == text)) {
                    return Err("is inconsistent with another secret of the same text".to_owned());
                }
                secrets.push((*n, text.to_owned()));
                Ok(())
            }
            Placeholder::SecretPrefix(n) => {
                if self.bound(Family::Secret, *n).is_none() {
                    owed.push(Owed::Prefix(*n, text.to_owned()));
                }
                Ok(())
            }
            Placeholder::SecretHash(n) => {
                if self.bound(Family::Secret, *n).is_none() {
                    owed.push(Owed::Hash(*n, text.to_owned()));
                }
                Ok(())
            }
            Placeholder::PasswordHash(PasswordOf::Fixture) => {
                if self.verifies(FIXTURE_PASSWORD, text) {
                    Ok(())
                } else {
                    Err("does not hold the fixture's passphrase".to_owned())
                }
            }
            Placeholder::PasswordHash(PasswordOf::Secret(n)) => match self.bound(Family::Secret, *n).map(str::to_owned)
            {
                Some(secret) if self.verifies(&secret, text) => Ok(()),
                Some(_) => Err(format!("does not hold secret {n}")),
                None => {
                    owed.push(Owed::Password(*n, text.to_owned()));
                    Ok(())
                }
            },
            // The recorder tried the fixture and every password the test sent: none verified.
            Placeholder::PasswordHash(PasswordOf::Unknown) => {
                if self.verifies(FIXTURE_PASSWORD, text) {
                    Err("holds the fixture's passphrase".to_owned())
                } else {
                    Ok(())
                }
            }
            Placeholder::Digest(n) | Placeholder::DigestPrefix(n) => {
                ordinal(Family::Digest, *n, text.to_ascii_lowercase(), proposed)
            }
            Placeholder::Port(n) => ordinal(Family::Port, *n, text.to_owned(), proposed),
            Placeholder::Uuid(n) => ordinal(Family::Uuid, *n, text.to_ascii_lowercase(), proposed),
            Placeholder::Long(n) => ordinal(Family::Long, *n, text.to_owned(), proposed),
            Placeholder::Pem { ordinal: n, .. } => ordinal(Family::Pem, *n, text.to_owned(), proposed),
            Placeholder::Date | Placeholder::DateTime | Placeholder::Instant | Placeholder::Stamp => {
                let (year, month, day) = digits_of(text).ok_or_else(|| format!("{text:?} is not a date"))?;
                if in_window(self.today, year, month, day) {
                    Ok(())
                } else {
                    Err(format!("{text:?} is outside the recorder's window"))
                }
            }
            Placeholder::HttpDate => {
                let year = text
                    .split(' ')
                    .nth(3)
                    .and_then(|year| year.parse().ok())
                    .ok_or_else(|| format!("{text:?} has no year"))?;
                if in_window(self.today, year, 1, 1) {
                    Ok(())
                } else {
                    Err(format!("{text:?} is outside the recorder's window"))
                }
            }
            Placeholder::OneTimeCode => {
                if ONE_TIME_CODE_FIELDS.contains(&field) {
                    Ok(())
                } else {
                    Err(format!("a one-time code under `{field}`"))
                }
            }
            Placeholder::Window | Placeholder::Sealed | Placeholder::ClockStep => Ok(()),
        }
    }
}

/// A template that is one identity or one long number and nothing else: the recorder turned a JSON integer into it.
fn integer_placeholder(template: &str) -> bool {
    matches!(
        segments(template).as_slice(),
        [Segment::Placeholder(Placeholder::Id { .. } | Placeholder::Long(_) | Placeholder::ClockStep)]
    )
}

/// Two numbers as decimals: `10.50` and `10.5` agree, as two engines' texts of one value should.
fn same_number(left: &str, right: &str) -> bool {
    fn canonical(text: &str) -> String {
        let (sign, digits) = text.strip_prefix('-').map_or(("", text), |rest| ("-", rest));
        let (whole, fraction) = digits.split_once('.').unwrap_or((digits, ""));
        let whole = whole.trim_start_matches('0');
        let fraction = fraction.trim_end_matches('0');
        let body = format!(
            "{}{}{}",
            if whole.is_empty() { "0" } else { whole },
            if fraction.is_empty() { "" } else { "." },
            fraction
        );
        if body == "0" { body } else { format!("{sign}{body}") }
    }
    left == right || (!left.contains(['e', 'E']) && !right.contains(['e', 'E']) && canonical(left) == canonical(right))
}

/// How numbers are held: an answer's as Jackson wrote them, a row's by value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumberText {
    Exact,
    Value,
}

impl Bindings<'_> {
    /// Holds `actual` to the recorded `expected`, member by member: objects as unordered maps (Java serialises some
    /// `Map.of` in an order the JVM draws at start-up — README § Bodies), arrays in order, strings as templates. Every
    /// difference is pushed to `out` with its JSON Pointer.
    pub fn match_json(
        &mut self,
        expected: &Json,
        actual: &Json,
        field: &str,
        numbers: NumberText,
        pointer: &str,
        out: &mut Vec<String>,
    ) {
        let at = if pointer.is_empty() { "/" } else { pointer };
        match (expected, actual) {
            (Json::Str(template), Json::Str(text)) => {
                if let Err(why) = self.match_text(template, text, field) {
                    out.push(format!("{at}: {why}"));
                }
            }
            // An integer the recorder wrote as an identity or a long number: the number must be that one. Its type
            // is the contract's to hold (the schema check of the answer) or the column's (a row).
            (Json::Str(template), Json::Num(text)) if integer_placeholder(template) => {
                if let Err(why) = self.match_text(template, text, field) {
                    out.push(format!("{at}: {why}"));
                }
            }
            (Json::Num(left), Json::Num(right)) => {
                let same = match numbers {
                    NumberText::Exact => left == right,
                    NumberText::Value => same_number(left, right),
                };
                if !same {
                    out.push(format!("{at}: {right}, recorded {left}"));
                }
            }
            (Json::Bool(left), Json::Bool(right)) if left == right => {}
            (Json::Null, Json::Null) => {}
            (Json::Arr(left), Json::Arr(right)) => {
                if left.len() != right.len() {
                    out.push(format!("{at}: {} elements, recorded {}", right.len(), left.len()));
                    return;
                }
                for (index, (left, right)) in left.iter().zip(right).enumerate() {
                    self.match_json(left, right, field, numbers, &format!("{pointer}/{index}"), out);
                }
            }
            (Json::Obj(left), Json::Obj(right)) => {
                for (name, value) in left {
                    let child = format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1"));
                    match right.iter().find(|(other, _)| other == name) {
                        Some((_, other)) => self.match_json(value, other, name, numbers, &child, out),
                        None => out.push(format!("{child}: absent, recorded {}", value.to_text())),
                    }
                }
                for (name, value) in right {
                    if !left.iter().any(|(other, _)| other == name) {
                        out.push(format!("{pointer}/{name}: {}, not recorded", value.to_text()));
                    }
                }
            }
            (left, right) => out.push(format!("{at}: {}, recorded {}", right.to_text(), left.to_text())),
        }
    }
}

fn describe(placeholder: &Placeholder) -> String {
    format!("{placeholder:?}")
}

/// A clock value as a row stores it (`2026-10-18 10:15:30.000001`) or as the wire carries it (ISO-8601, with `Z`
/// for an instant).
fn clock_text(at: OffsetDateTime, context: Context, instant: bool) -> String {
    let date = at.date();
    let time = at.time();
    let separator = if context == Context::Row { ' ' } else { 'T' };
    let zone = if instant && context == Context::Wire { "Z" } else { "" };
    format!(
        "{date}{separator}{:02}:{:02}:{:02}.{:06}{zone}",
        time.hour(),
        time.minute(),
        time.second(),
        time.microsecond()
    )
}

/// How each secret of a test is minted when the replay must mint it: an API key when its prefix is ever shown.
#[must_use]
pub fn secret_kinds<'a>(texts: impl IntoIterator<Item = &'a str>) -> BTreeMap<u32, SecretKind> {
    let mut kinds = BTreeMap::new();
    for text in texts {
        for segment in segments(text) {
            match segment {
                Segment::Placeholder(Placeholder::SecretPrefix(n)) => {
                    kinds.insert(n, SecretKind::ApiKey);
                }
                Segment::Placeholder(Placeholder::Secret(n)) => {
                    kinds.entry(n).or_insert(SecretKind::Token);
                }
                Segment::Literal(_) | Segment::Placeholder(_) => {}
            }
        }
    }
    kinds
}

/// `TrafficRecorder.dropUnchangedUpdates`, for what the Rust side changed: a column whose old and new values render
/// alike — an instant moved within the window, one sealed value for another — is not a change the recording keeps.
/// Only the rules that number nothing collapse two values; two ids, two UUIDs or two digests stay different, as
/// their ordinals would.
#[must_use]
pub fn renders_alike(today: Date, column: &str, from: &str, to: &str) -> bool {
    if from == to {
        return true;
    }
    collapse(today, column, from) == collapse(today, column, to)
}

fn collapse(today: Date, column: &str, text: &str) -> String {
    static CLOCK: LazyLock<Regex> = LazyLock::new(|| {
        pattern(
            r"([0-9]{4})-([0-9]{2})-([0-9]{2})(?:([T ])[0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:[.,][0-9]{1,9})?)?(Z|[+-][0-9]{2}:?[0-9]{2})?)?",
        )
    });
    static SEALED: LazyLock<Regex> = LazyLock::new(|| pattern(r"v2:[A-Za-z0-9+/_-]+=*"));
    let column = column.to_ascii_lowercase();
    if column == "totp_last_step" || column == "totplaststep" {
        return "«clock-step»".to_owned();
    }
    let sealed = SEALED.replace_all(text, "«sealed»");
    CLOCK
        .replace_all(&sealed, |found: &regex::Captures<'_>| {
            let whole = found.get(0).map_or("", |all| all.as_str());
            let in_range = digits_of(whole).is_some_and(|(year, month, day)| in_window(today, year, month, day));
            if !in_range {
                whole.to_owned()
            } else if found.get(4).is_none() {
                "«date»".to_owned()
            } else if found.get(5).is_none() {
                "«datetime»".to_owned()
            } else {
                "«instant»".to_owned()
            }
        })
        .into_owned()
}
