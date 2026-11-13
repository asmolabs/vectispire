package com.asmolabs.vectispire.core.golden;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.crypto.ResultAttestation;
import com.asmolabs.vectispire.common.domain.crypto.SealingKeyAttestation;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

/**
 * One test's placeholders: what a golden file says instead of a value that changes from run to run.
 *
 * <p><b>Ordinals, per test, in the order a value is first rendered.</b> The same token, UUID or
 * nanosecond suffix gets the same placeholder in every file of the test that saw it, so a replay can
 * still check that the session a response names is the one the request presented. A value that would
 * not have changed between runs gains nothing from being replaced, and loses nothing either: its
 * ordinal is as stable as it is — which is why the rules below err towards replacing.
 *
 * <p><b>Secrets are collected before anything is rendered</b> ({@link #collect}): a session's hash
 * is written in a row of the seed, which the file shows before the response that minted the token,
 * and rendered first it would stay a literal hash of a random value.
 *
 * <p>The rules, and their order, are the golden format's — README.md beside this class states them for
 * the replay runner, which applies the same ones to what it observes before comparing.
 */
final class Placeholders {

    /** The passphrase {@code ApiTestBase} gives every account it mints: a fixture in the source, not a secret. */
    static final String FIXTURE_PASSWORD = "correct horse battery staple";

    /**
     * Fields whose string value is a credential, wherever they appear — a request body, a response
     * body. Matched case-insensitively on the whole name. Not {@code key} (settings keys) and not
     * {@code code} (error codes): a value registered here is replaced everywhere in the test.
     */
    private static final Set<String> SECRET_FIELDS = Set.of(
            "token", "accesstoken", "refreshtoken", "sessiontoken", "bearertoken", "apikey", "fullkey", "plainkey",
            "secret", "clientsecret", "totpsecret", "webhooksecret", "signingsecret", "password", "newpassword",
            "currentpassword", "oldpassword", "recoverycodes", "recoverycode", "scimtoken", "agentkey", "plaintext",
            "privatekey", "passphrase", "credential", "authtoken", "handofftoken", "backupcodes", "backupcode");

    /** A one-time code: derived from a random secret and the clock, so never the same twice. */
    private static final Set<String> ONE_TIME_CODE_FIELDS = Set.of("code", "totp", "totpcode", "mfacode", "otp");
    private static final Pattern ONE_TIME_CODE = Pattern.compile("\\d{6,8}|[a-z0-9]{4}-[a-z0-9]{4}");

    /** Integers counted from the epoch: the TOTP step a code was last accepted at. */
    private static final Set<String> CLOCK_COUNTERS = Set.of("totp_last_step", "totplaststep");

    /** A digest cut short in a sentence, {@code evidence sha256 84d6de6c0a57}: of a document holding a date. */
    private static final Pattern NAMED_DIGEST_PREFIX =
            Pattern.compile("(?i)(sha-?256[ :])([0-9a-f]{8,63})(?![0-9a-f])");

    /** A digest left once the known secrets' have been named: a chain link, a hash of something random. */
    private static final Pattern HEX_DIGEST = Pattern.compile("(?i)[0-9a-f]{32,128}");

    /** {@code RateWindows}' key, {@code <limit>:<window number>:<subject digest>}: the number is the clock's. */
    private static final Pattern RATE_WINDOW = Pattern.compile("^([A-Za-z0-9_-]+):\\d+:");

    /** API keys: {@code ApiKeys.generate()}'s shape. Their stored prefix is their first twelve characters. */
    private static final Pattern API_KEY = Pattern.compile("zsk_[A-Za-z0-9_-]{43}");
    private static final int API_KEY_PREFIX = 12;

    /**
     * Thirty-two random bytes, base64url without padding: a session token, an agent key, a hand-off. Not
     * a slice of standard base64 between a {@code +} and a {@code /}: registered, it was never shown,
     * and every ordinal after it moved by one between runs.
     */
    private static final Pattern RANDOM_TOKEN =
            Pattern.compile("(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_+/=-])");

    /**
     * Base64 or base64url of random bytes, padded or not: an agent's sealing or signing public key, an
     * ECDSA signature (whose DER length varies, so its padding does too). Bounded at 200 characters:
     * a registered value is looked for in every string the test renders after it.
     */
    private static final Pattern RANDOM_BASE64 =
            Pattern.compile("(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{40,200}={0,2}(?![A-Za-z0-9+/=_-])");

    /** A PEM block: the suites generate their certificate authorities and keys at every run. */
    private static final Pattern PEM = Pattern.compile("-----BEGIN ([A-Z0-9 ]+)-----[\\s\\S]*?-----END \\1-----");

    /** A loopback port: the stub servers the tests stand up listen wherever the system put them. */
    private static final Pattern LOOPBACK_PORT = Pattern.compile("(127\\.0\\.0\\.1|localhost|\\[::1\\]):(\\d{2,5})(?![0-9])");

    private static final Pattern UUID = Pattern.compile(
            "(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])");

    /** Argon2id and bcrypt, salted at random: never the same twice. */
    private static final Pattern PASSWORD_HASH =
            Pattern.compile("\\$argon2(?:id|i|d)\\$[^\\s\"]+|\\$2[abxy]?\\$\\d{2}\\$[./A-Za-z0-9]{53}");

    /** {@link SecretCipher}'s format: nonce, text and tag, the nonce random. */
    private static final Pattern SEALED =
            Pattern.compile(Pattern.quote(SecretCipher.FORMAT_PREFIX) + "[A-Za-z0-9+/_-]+=*");

    /**
     * {@code System.nanoTime()} and {@code currentTimeMillis()} suffixes: {@code ApiTestBase} names its
     * accounts {@code admin-<nanoTime>}. Twelve digits or more, never an identity ({@link RowSnapshots}, nine).
     */
    private static final Pattern LONG_NUMBER = Pattern.compile("(?<![0-9A-Za-z])[0-9]{12,19}(?![0-9A-Za-z])");

    /** ISO dates, date-times and instants; the window decides whether one is the clock's. */
    private static final Pattern ISO_DATE_TIME = Pattern.compile(
            "(?<![0-9])(\\d{4})-(\\d{2})-(\\d{2})(?:([T ])\\d{2}:\\d{2}(?::\\d{2}(?:[.,]\\d{1,9})?)?(Z|[+-]\\d{2}:?\\d{2})?)?(?![0-9])");

    /** RFC 1123, the HTTP date: {@code Expires}, {@code Last-Modified}, a cookie's expiry. */
    private static final Pattern HTTP_DATE = Pattern.compile(
            "(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \\d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\\d{4}) \\d{2}:\\d{2}:\\d{2} GMT");

    /** Compact stamps in file names: {@code 20261016T101500Z}, {@code 20261016-1015}. */
    private static final Pattern COMPACT_STAMP =
            Pattern.compile("(?<![0-9])(\\d{4})(\\d{2})(\\d{2})(?:T\\d{4,6}Z?|-\\d{4,6})(?![0-9])");

    /**
     * Dates within this window are the clock's: three years back covers a test that seeds "a year
     * ago", eleven ahead an API key's longest lifetime. A literal a test wrote inside it is replaced
     * too, which costs a value the replay could have checked and never makes a golden unstable; one
     * outside — {@code 2020-01-01}, the year 9999 — stays.
     */
    private static final LocalDate TODAY = LocalDate.now(ZoneOffset.UTC);
    private static final LocalDate WINDOW_FROM = TODAY.minusYears(3);
    private static final LocalDate WINDOW_TO = TODAY.plusYears(11);

    private final Map<String, Integer> secrets = new LinkedHashMap<>();
    private final Map<String, Integer> secretHashes = new HashMap<>();
    private final Map<String, Integer> apiKeyPrefixes = new HashMap<>();
    private final Map<String, Integer> passwordCandidates = new LinkedHashMap<>();
    private final Map<String, String> passwordHashes = new HashMap<>();
    private final Map<String, Integer> uuids = new HashMap<>();
    private final Map<String, Integer> longNumbers = new HashMap<>();
    private final Map<String, Integer> digests = new HashMap<>();
    private final Map<String, Integer> pems = new HashMap<>();
    private final Map<String, Integer> ports = new HashMap<>();
    /** A sealing-key announcement's signature the recorder could re-make, and the computation that makes it. */
    private final Map<String, String> sealingSignatures = new HashMap<>();
    /** The record being rendered's attestation on a result or a failure report, when the replay can make it again. */
    private final Map<String, String> resultSignatures = new HashMap<>();
    /** Identity guards recognised as the digest of an identity the recording shows as it is. */
    private final Set<String> literalGuards = new java.util.HashSet<>();
    private List<String> secretsLongestFirst = List.of();

    /** A table's identities: its base, and the first one this test may create. */
    record IdRange(String table, long base, long start) {}

    /** Nine digits, the identities' length ({@link RowSnapshots#idBases}), alone. */
    private static final Pattern IDENTITY = Pattern.compile("(?<![0-9A-Za-z])[1-9][0-9]{8}(?![0-9A-Za-z])");

    private final Map<Long, IdRange> rangesByBase = new HashMap<>();
    private long idStride = 1;

    /** The tables' ranges, read when the test starts: an identity is written as its rank among them. */
    void identities(List<IdRange> ranges, long stride) {
        rangesByBase.clear();
        ranges.forEach(range -> rangesByBase.put(range.base(), range));
        idStride = stride;
    }

    /**
     * {@code «t_repository#1»}: the first repository this test created, whatever number the server gave
     * it — the number depends on every test that ran before. An identity created before the test
     * (none should be: the harness empties the tables) is {@code «t_repository#prior»}.
     */
    private String identity(long value) {
        IdRange range = rangesByBase.get(value - value % idStride);
        if (range == null) {
            return null;
        }
        long rank = value - range.start() + 1;
        return "«" + range.table() + "#" + (rank >= 1 ? String.valueOf(rank) : "prior") + "»";
    }

    /** Registers a credential: it, its SHA-256 and, for an API key, its stored prefix are replaced from now on. */
    void registerSecret(String value) {
        if (value == null || value.length() < 6 || value.equals(FIXTURE_PASSWORD) || value.startsWith("«")
                || secrets.containsKey(value) || FixtureSealingKeys.isFixture(value)
                || sealingSignatures.containsKey(value) || resultSignatures.containsKey(value)
                || oneCharacterRepeated(value)) {
            return;
        }
        int ordinal = secrets.size() + 1;
        secrets.put(value, ordinal);
        secretHashes.put(sha256Hex(value), ordinal);
        if (API_KEY.matcher(value).matches()) {
            apiKeyPrefixes.put(value.substring(0, API_KEY_PREFIX), ordinal);
            // An API key is stored as its Argon2id hash, which a replay seeding the row must recompute.
            passwordCandidates.putIfAbsent(value, passwordCandidates.size());
        }
        List<String> sorted = new ArrayList<>(secrets.keySet());
        sorted.sort(Comparator.comparingInt(String::length).reversed());
        secretsLongestFirst = sorted;
    }

    /**
     * {@code "t".repeat(8_193)}: a bound's padding under a credential's name, not a credential — one character
     * repeated carries nothing to guess. Hidden, its length went with it, and the replay sent a token the bound let
     * through ({@code IntegrationInputBoundsTest}). A short token ({@code ghp_abc}) is still a secret.
     */
    private static boolean oneCharacterRepeated(String value) {
        return value.chars().distinct().count() == 1;
    }

    /** A password-shaped secret, tried against the password hashes the rows hold. */
    private void registerPassword(String value) {
        registerSecret(value);
        if (value != null && !value.isEmpty()) {
            passwordCandidates.putIfAbsent(value, passwordCandidates.size());
        }
    }

    /**
     * A value with everything random masked and nothing numbered: the order rows keyed by a random UUID
     * are shown in. Sorted by their raw key, two such rows swapped places from one run to the next, and
     * the ordinals their values were given in that order swapped with them.
     */
    static String mask(String text) {
        String out = PASSWORD_HASH.matcher(text).replaceAll("P");
        out = SEALED.matcher(out).replaceAll("S");
        out = API_KEY.matcher(out).replaceAll("K");
        out = UUID.matcher(out).replaceAll("U");
        out = ISO_DATE_TIME.matcher(out).replaceAll("D");
        out = HEX_ANY.matcher(out).replaceAll("H");
        out = RANDOM_TOKEN.matcher(out).replaceAll("T");
        return LONG_NUMBER.matcher(out).replaceAll("N");
    }

    private static final Pattern HEX_ANY = Pattern.compile("(?i)(?<![0-9a-z])[0-9a-f]{32,}(?![0-9a-z])");

    /**
     * The first pass: registers every credential a record carries, before any of it is rendered. Called on a whole
     * record ({@code fieldName} null), its {@code request} is read as what the test sent ({@link #isEcdsaSignature}).
     */
    void collect(JsonNode node, String fieldName) {
        if (fieldName == null && node != null && node.isObject()) {
            recogniseSealingSignature(node.path("request").path("body").path("json"));
            recogniseResultSignature(node.path("request"));
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                collect(field.getValue(), field.getKey(), field.getKey().equals("request"));
            }
            return;
        }
        collect(node, fieldName, false);
    }

    private void collect(JsonNode node, String fieldName, boolean sentByTheTest) {
        if (node == null) {
            return;
        }
        if (node.isObject()) {
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                collect(field.getValue(), field.getKey(), sentByTheTest);
            }
        } else if (node.isArray()) {
            for (JsonNode element : node) {
                collect(element, fieldName, sentByTheTest);
            }
        } else if (node.isTextual()) {
            String text = node.asText();
            boolean stored = PASSWORD_HASH.matcher(text).matches() || SEALED.matcher(text).matches();
            if (!stored && fieldName != null && SECRET_FIELDS.contains(fieldName.toLowerCase(Locale.ROOT))) {
                if (fieldName.toLowerCase(Locale.ROOT).contains("password")) {
                    registerPassword(text);
                } else {
                    registerSecret(text);
                }
            }
            collectPatterns(text, sentByTheTest);
        }
    }

    /** Credentials recognised by their shape alone. */
    void collectPatterns(String raw) {
        collectPatterns(raw, false);
    }

    private void collectPatterns(String raw, boolean sentByTheTest) {
        // Not inside a stored form: an Argon2 hash or a sealed value is random, not a credential presented.
        String text = SEALED.matcher(PASSWORD_HASH.matcher(PEM.matcher(raw).replaceAll(" ")).replaceAll(" ")).replaceAll(" ");
        Matcher keys = API_KEY.matcher(text);
        while (keys.find()) {
            registerSecret(keys.group());
        }
        Matcher padded = RANDOM_BASE64.matcher(text);
        while (padded.find()) {
            String candidate = padded.group();
            if (looksLikeAPath(candidate)) {
                // A path is read by its segments: a route's words are not secret, and a random segment of it
                // (a badge's token) is. Tokens after a slash are out of RANDOM_TOKEN's reach on the whole string.
                for (String segment : candidate.split("/")) {
                    if (!segment.isEmpty()) {
                        collectPatterns(segment, sentByTheTest);
                    }
                }
            } else if (sentByTheTest && isEcdsaSignature(candidate)) {
                // Kept: a signature the test sends — over a document it wrote, with the context's fixture key or a key
                // pair whose public half it sends beside it — is what the replay must send for the route to verify
                // it, and it is no credential. Hidden, it was «secret:N», which the replay filled with random bytes:
                // /api/v1/crypto/verify could only answer "invalid". One the server answered, or stored, is still
                // registered (wherever else in the record it shows): Java draws k at random where Rust's is
                // deterministic, so the same document has two valid signatures, and only a placeholder matches both.
                continue;
            } else if (looksRandom(candidate)) {
                registerSecret(candidate);
            }
        }
        Matcher tokens = RANDOM_TOKEN.matcher(text);
        while (tokens.find()) {
            String token = tokens.group();
            if (looksRandom(token)) {
                registerSecret(token);
            }
        }
    }

    /** An {@code Authorization} header's credential, whatever its scheme. */
    void collectAuthorization(String value) {
        int space = value.indexOf(' ');
        registerSecret(space < 0 ? value : value.substring(space + 1).trim());
    }

    /** A cookie's value is a hand-off token or a session: random, whatever its name. */
    void collectCookie(String setCookieOrValue) {
        String pair = setCookieOrValue.split(";", 2)[0];
        int equals = pair.indexOf('=');
        if (equals > 0 && equals < pair.length() - 1) {
            registerSecret(pair.substring(equals + 1));
        }
    }

    /** The second pass: a copy of the tree with every rule applied to every string. */
    JsonNode render(JsonNode node) {
        return render(node, null);
    }

    /**
     * The field a value sits in decides three rules the value alone cannot: a one-time code, a digest
     * nothing else names, a rate window's number.
     */
    private JsonNode render(JsonNode node, String fieldName) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return node;
        }
        if (node.isObject()) {
            recogniseIdentityGuard(node);
            // An updated row's column holds {from, to}: both are still that column's values.
            boolean change = fieldName != null && node.size() == 2 && node.has("from") && node.has("to");
            ObjectNode copy = JsonNodeFactory.instance.objectNode();
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                copy.set(field.getKey(), render(field.getValue(), change ? fieldName : field.getKey()));
            }
            return copy;
        }
        if (node.isArray()) {
            ArrayNode copy = JsonNodeFactory.instance.arrayNode();
            node.forEach(element -> copy.add(render(element, fieldName)));
            return copy;
        }
        if (node.isTextual()) {
            String field = fieldName == null ? "" : fieldName.toLowerCase(Locale.ROOT);
            String text = node.asText();
            if (ONE_TIME_CODE_FIELDS.contains(field) && ONE_TIME_CODE.matcher(text).matches()) {
                return JsonNodeFactory.instance.textNode("«one-time-code»");
            }
            // t_repository.identity_guard, when it is the guard of an identity its own row shows literally
            // (literalGuards): kept, so the replay seeds Java's digest and Rust's must equal it.
            if (field.equals("identity_guard") && literalGuards.contains(text)) {
                return JsonNodeFactory.instance.textNode(text);
            }
            if (field.equals("window_key")) {
                text = RATE_WINDOW.matcher(text).replaceFirst("$1:«window»:");
            }
            String rendered = render(text);
            if (field.contains("hash") && HEX_DIGEST.matcher(rendered).matches()) {
                rendered = "«sha256:" + digests.computeIfAbsent(rendered.toLowerCase(Locale.ROOT),
                        key -> digests.size() + 1) + "»";
            }
            return JsonNodeFactory.instance.textNode(rendered);
        }
        if (node.isIntegralNumber() && CLOCK_COUNTERS.contains(fieldName == null ? "" : fieldName.toLowerCase(Locale.ROOT))) {
            return JsonNodeFactory.instance.textNode("«clock-step»");
        }
        if (node.isIntegralNumber() && node.canConvertToLong()) {
            String id = identity(node.asLong());
            if (id != null) {
                return JsonNodeFactory.instance.textNode(id);
            }
        }
        if (node.isIntegralNumber() && LONG_NUMBER.matcher(node.asText()).matches()) {
            return JsonNodeFactory.instance.textNode(longNumber(node.asText()));
        }
        return node;
    }

    /** Every rule, in the format's order, on one string. */
    String render(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String resigned = sealingSignatures.get(text);
        if (resigned != null) {
            return resigned;
        }
        for (Map.Entry<String, String> attested : resultSignatures.entrySet()) {
            text = text.replace(attested.getKey(), attested.getValue());
        }
        // A PEM block whole, before anything inside it is read as a token. **A certificate stays literal**: it is
        // public, and an answer states what it reads from one — the subject, the expiry — so a replay sending a
        // placeholder in its place could answer nothing Java answered (the SIEM's collector CA, refused or pinned).
        // **So does a public key**, for the same reason: a signature is checked against it, and a placeholder in its
        // place left the replay no key the signature was made with (a forger's key sent to /api/v1/crypto/verify);
        // the context's own is the suite's fixture (FixtureSigningKey), the same in the replay. Either is set aside
        // while the rules run, so that no base64 run of its body is read as a token. A private key is a
        // placeholder: no private key reaches a golden — but for the suites' invented ones (FixturePrivateKeys),
        // matched by fingerprint: the replay has to send what the test sent, and a placeholder is nothing to send.
        List<String> certificates = new ArrayList<>();
        String out = replace(text, PEM, match -> {
            if (isPublic(match.group(1)) || FixturePrivateKeys.isFixture(match.group())) {
                certificates.add(match.group());
                return CERTIFICATE_SET_ASIDE + (certificates.size() - 1) + CERTIFICATE_SET_ASIDE;
            }
            return "«pem:" + match.group(1).toLowerCase(Locale.ROOT).replace(' ', '-') + ":"
                    + pems.computeIfAbsent(match.group(), key -> pems.size() + 1) + "»";
        });
        // Stored forms next: an Argon2 hash carries 43 base64 characters that would otherwise read as a token.
        out = replace(out, PASSWORD_HASH, match -> passwordHash(match.group()));
        out = replace(out, SEALED, match -> "«sealed»");
        out = replaceHashesOfSecrets(out);
        for (String secret : secretsLongestFirst) {
            if (out.contains(secret)) {
                out = out.replace(secret, "«secret:" + secrets.get(secret) + "»");
            }
        }
        for (Map.Entry<String, Integer> prefix : apiKeyPrefixes.entrySet()) {
            if (out.contains(prefix.getKey())) {
                out = out.replace(prefix.getKey(), "«secret:" + prefix.getValue() + ":prefix»");
            }
        }
        // A digest no secret accounts for: a document's, a chain link's, a manifest's. Many are the same on
        // every run, but a document holding a date is not, and its digest names it in a path.
        out = replace(out, HEX_64, match -> "«sha256:" + digests.computeIfAbsent(
                match.group().toLowerCase(Locale.ROOT), key -> digests.size() + 1) + "»");
        out = replace(out, NAMED_DIGEST_PREFIX, match -> match.group(1) + "«sha256-prefix:"
                + digests.computeIfAbsent(match.group(2).toLowerCase(Locale.ROOT), key -> digests.size() + 1) + "»");
        out = replace(out, LOOPBACK_PORT, match -> match.group(1) + ":«port:"
                + ports.computeIfAbsent(match.group(2), key -> ports.size() + 1) + "»");
        out = replace(out, UUID, match -> "«uuid:" + uuids.computeIfAbsent(
                match.group().toLowerCase(Locale.ROOT), key -> uuids.size() + 1) + "»");
        out = replace(out, ISO_DATE_TIME, Placeholders::isoDateTime);
        out = replace(out, HTTP_DATE, match -> inWindow(Integer.parseInt(match.group(1)), 1, 1)
                ? "«http-date»" : match.group());
        out = replace(out, COMPACT_STAMP, match -> inWindow(match) ? "«stamp»" : match.group());
        out = replace(out, IDENTITY, match -> {
            String id = identity(Long.parseLong(match.group()));
            return id == null ? match.group() : id;
        });
        out = replace(out, LONG_NUMBER, match -> longNumber(match.group()));
        for (int i = 0; i < certificates.size(); i++) {
            out = out.replace(CERTIFICATE_SET_ASIDE + i + CERTIFICATE_SET_ASIDE, certificates.get(i));
        }
        return out;
    }

    /**
     * {@code POST /api/v1/agent/sealing-key}'s signature, when the replay can make it again: {@code
     * «sealing-signature:v2:secret:S:uuid:U:<generation>:<key>»}, the Ed25519 signature of {@link SealingKeyAttestation}
     * ({@code v1}: of an agent from before bound envelopes) by the seed {@code «secret:S»} over agent {@code «uuid:U»},
     * that generation and that key.
     *
     * <p><b>Why a computation, and not the value.</b> Ed25519 is deterministic, but what it signs is not: the agent's
     * id, which the server draws at enrolment, and the seed, which {@code "public_key": "generate"} draws at pinning.
     * Hidden as {@code «secret:N»}, the replay sent a minted token and no announcement could be accepted; kept, it
     * would be a signature over Java's agent, which the replay's agent is not. Named this way, the replay signs with
     * the seed its own server answered and for its own agent's id — what an agent does.
     *
     * <p>Only when it verifies, under a seed the test has shown and for an agent the test has named, over a key that
     * is a fixture ({@link FixtureSealingKeys}): a signature by a key the test kept to itself, or moved onto another
     * key, is still a {@code «secret:N»} — the replay sends something else that does not verify, as Java's did not.
     */
    private void recogniseSealingSignature(JsonNode body) {
        JsonNode signature = body.path("signature");
        JsonNode key = body.path("public_key");
        JsonNode generation = body.path("generation");
        if (!signature.isTextual() || !key.isTextual() || !generation.canConvertToLong()
                || !FixtureSealingKeys.isFixture(key.asText()) || sealingSignatures.containsKey(signature.asText())) {
            return;
        }
        for (Map.Entry<String, Integer> seed : secrets.entrySet()) {
            String publicKey = ed25519PublicKey(seed.getKey());
            if (publicKey == null) {
                continue;
            }
            for (Map.Entry<String, Integer> agent : uuids.entrySet()) {
                java.util.UUID id = java.util.UUID.fromString(agent.getKey());
                String version = SealingKeyAttestation.verify(
                                publicKey, id, generation.asLong(), key.asText(), signature.asText())
                        ? "v2"
                        : SealingKeyAttestation.signedByAPreviousAgent(
                                        publicKey, id, generation.asLong(), key.asText(), signature.asText())
                                ? "v1"
                                : null;
                if (version != null) {
                    sealingSignatures.put(signature.asText(), "«sealing-signature:" + version + ":secret:" + seed.getValue()
                            + ":uuid:" + agent.getValue() + ":" + generation.asLong() + ":" + key.asText() + "»");
                    return;
                }
            }
        }
    }

    /** {@code /api/v1/agent/jobs/{id}/result} or {@code /failure}: the routes {@link ResultAttestation} signs for. */
    private static final Pattern ATTESTED_ROUTE = Pattern.compile("^/api/v1/agent/jobs/([0-9]+)/(result|failure)$");

    /**
     * An agent's attestation on a result or a failure report ({@link ResultAttestation#HEADER}), when the replay can
     * make it again: {@code «result-signature:failure:secret:S»}, the Ed25519 signature by the seed {@code «secret:S»}
     * of the scan the path names and of the request's bytes.
     *
     * <p><b>Why a computation, and not the value</b> — as for the sealing key: the seed is drawn by {@code
     * "public_key": "generate"} and the scan's id by the server, so Java's signature verifies for neither of the
     * replay's. Hidden as {@code «secret:N»}, the replay sent random bytes, and a result its agent had signed was
     * refused. The bytes are the body as recorded (compact JSON, its members sorted, or its text): a test whose body
     * was written otherwise does not verify here and stays a {@code «secret:N»}, the replay sending something else that
     * does not verify. So does a signature by a key the test kept to itself.
     */
    private void recogniseResultSignature(JsonNode request) {
        // This record's only: the same value sent again to another scan (noReplayAcrossScans) verifies for nothing
        // there, and named as a computation the replay would sign it for that scan and see it accepted.
        resultSignatures.clear();
        Matcher route = ATTESTED_ROUTE.matcher(request.path("path").asText(""));
        if (!route.matches()) {
            return;
        }
        String signature = null;
        for (JsonNode header : request.path("headers")) {
            String line = header.asText();
            if (line.regionMatches(true, 0, ResultAttestation.HEADER + ": ", 0, ResultAttestation.HEADER.length() + 2)) {
                signature = line.substring(ResultAttestation.HEADER.length() + 2);
            }
        }
        if (signature == null || resultSignatures.containsKey(signature)) {
            return;
        }
        JsonNode body = request.path("body");
        byte[] bytes = body.has("json") ? body.get("json").toString().getBytes(StandardCharsets.UTF_8)
                : body.has("text") ? body.get("text").asText().getBytes(StandardCharsets.UTF_8)
                : body.isMissingNode() ? new byte[0] : null;
        if (bytes == null) {
            return;
        }
        long scanId = Long.parseLong(route.group(1));
        for (Map.Entry<String, Integer> seed : secrets.entrySet()) {
            String publicKey = ed25519PublicKey(seed.getKey());
            if (publicKey == null) {
                continue;
            }
            String kind = ResultAttestation.verify(publicKey, scanId, bytes, signature) ? "result"
                    : ResultAttestation.verifyFailure(publicKey, scanId, bytes, signature) ? "failure"
                    : null;
            if (kind != null) {
                resultSignatures.put(signature, "«result-signature:" + kind + ":secret:" + seed.getValue() + "»");
                return;
            }
        }
    }

    /**
     * {@code t_repository.identity_guard} is {@code RepositoryIdentity.guard}: the SHA-256 of the repository's identity,
     * branch and sub-path, all public. Numbered, a guard the test seeded was replayed as a random digest that collided
     * with nothing, and a twin Java refused was accepted ({@code RepositoryDuplicatesRoutesTest}). Kept only when this
     * row — an inserted one, or an update's changes — shows the identity it hashes (branch and sub-path from the row,
     * {@code main} and the root when it does not show them), and that identity renders as it is: a repository named
     * {@code service-<nanoTime>} has a guard the replay's own name changes, which only a placeholder matches.
     */
    private void recogniseIdentityGuard(JsonNode row) {
        List<String> guards = columnValues(row.get("identity_guard"));
        List<String> identities = columnValues(row.get("url_identity"));
        if (guards.isEmpty() || identities.isEmpty()) {
            return;
        }
        List<String> branches = columnValues(row.get("branch"));
        List<String> subPaths = columnValues(row.get("sub_path"));
        for (String identity : identities) {
            if (!staysLiteral(identity)) {
                continue;
            }
            for (String branch : branches.isEmpty() ? List.of("main") : branches) {
                for (String subPath : subPaths.isEmpty() ? List.of("") : subPaths) {
                    String guard = Digests.sha256Fields(identity, branch, subPath);
                    if (guards.contains(guard)) {
                        literalGuards.add(guard);
                    }
                }
            }
        }
    }

    /**
     * Whether no rule would replace anything in this text — asked without rendering it, which would number what it
     * holds out of the order the file shows it in.
     */
    private boolean staysLiteral(String text) {
        return !LONG_NUMBER.matcher(text).find() && !IDENTITY.matcher(text).find() && !UUID.matcher(text).find()
                && !LOOPBACK_PORT.matcher(text).find() && !HEX_DIGEST.matcher(text).find()
                && !ISO_DATE_TIME.matcher(text).find() && secrets.keySet().stream().noneMatch(text::contains);
    }

    /** A row's column as written: its value, or an update's {@code from} and {@code to}; nulls left out. */
    private static List<String> columnValues(JsonNode column) {
        if (column == null) {
            return List.of();
        }
        if (column.isTextual()) {
            return List.of(column.asText());
        }
        List<String> values = new ArrayList<>();
        for (String side : List.of("from", "to")) {
            if (column.path(side).isTextual()) {
                values.add(column.path(side).asText());
            }
        }
        return values;
    }

    /** The public half of an Ed25519 seed, base64 as the control plane pins it; null for anything else. */
    private static String ed25519PublicKey(String base64Seed) {
        byte[] seed;
        try {
            seed = java.util.Base64.getDecoder().decode(base64Seed);
        } catch (IllegalArgumentException notBase64) {
            return null;
        }
        if (seed.length != Ed25519PrivateKeyParameters.KEY_SIZE) {
            return null;
        }
        return java.util.Base64.getEncoder().encodeToString(
                new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded());
    }

    /** A certificate or a public key: {@code CERTIFICATE}, {@code PUBLIC KEY}, {@code RSA PUBLIC KEY}. Not a private key. */
    private static boolean isPublic(String label) {
        return label.equals("CERTIFICATE") || label.equals("PUBLIC KEY") || label.endsWith(" PUBLIC KEY");
    }

    /** Brackets a certificate's index while the rules run: a character no recorded text holds. */
    private static final String CERTIFICATE_SET_ASIDE = "\u0000";

    private String replaceHashesOfSecrets(String text) {
        if (secretHashes.isEmpty() || text.length() < 64) {
            return text;
        }
        return replace(text, HEX_64, match -> {
            Integer ordinal = secretHashes.get(match.group().toLowerCase(Locale.ROOT));
            return ordinal == null ? match.group() : "«sha256(secret:" + ordinal + ")»";
        });
    }

    private static final Pattern HEX_64 = Pattern.compile("(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])");

    /**
     * A password hash says which password it holds when the recorder can tell: a replay seeding the
     * row has to hash the same password, or the sign-in it then replays is refused. Tried against the
     * fixture's passphrase and the passwords this test sent, each verification cached — Argon2 is
     * slow on purpose.
     */
    private String passwordHash(String encoded) {
        return passwordHashes.computeIfAbsent(encoded, hash -> {
            if (verifies(FIXTURE_PASSWORD, hash)) {
                return "«password-hash(" + FIXTURE_PASSWORD + ")»";
            }
            for (String candidate : passwordCandidates.keySet()) {
                if (verifies(candidate, hash)) {
                    return "«password-hash(secret:" + secrets.get(candidate) + ")»";
                }
            }
            return "«password-hash(?)»";
        });
    }

    private static boolean verifies(String password, String hash) {
        try {
            return PasswordHasher.verify(password, hash);
        } catch (RuntimeException unreadable) {
            return false;
        }
    }

    private String longNumber(String digits) {
        return "«n:" + longNumbers.computeIfAbsent(digits, key -> longNumbers.size() + 1) + "»";
    }

    private static String isoDateTime(Matcher match) {
        if (!inWindow(match)) {
            return match.group();
        }
        if (match.group(4) == null) {
            return "«date»";
        }
        return match.group(5) == null ? "«datetime»" : "«instant»";
    }

    private static boolean inWindow(Matcher match) {
        return inWindow(Integer.parseInt(match.group(1)), Integer.parseInt(match.group(2)),
                Integer.parseInt(match.group(3)));
    }

    private static boolean inWindow(int year, int month, int day) {
        if (month < 1 || month > 12 || day < 1 || day > 31) {
            return false;
        }
        LocalDate date;
        try {
            date = LocalDate.of(year, month, Math.min(day, LocalDate.of(year, month, 1).lengthOfMonth()));
        } catch (RuntimeException impossible) {
            return false;
        }
        return !date.isBefore(WINDOW_FROM) && !date.isAfter(WINDOW_TO);
    }

    /**
     * A request path is made of the characters base64 is made of, so a long one with a digit, a capital (a
     * profile such as {@code PO}) and a lower-case word passed {@link #looksRandom} and was registered as a
     * secret: the whole path was replaced by a placeholder, and its recording could no longer be matched to a
     * route. A path begins with a word between slashes ({@code /api/…}); a random string almost never does.
     */
    private static boolean looksLikeAPath(String candidate) {
        if (!candidate.startsWith("/") || candidate.chars().filter(c -> c == '/').count() < 3) {
            return false;
        }
        String first = candidate.substring(1, candidate.indexOf('/', 1));
        return !first.isEmpty() && first.chars().allMatch(c -> (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'));
    }

    /**
     * An ECDSA signature as {@code CosignSigner} writes it: base64 of a DER {@code SEQUENCE} of two {@code INTEGER}s,
     * every length agreeing. Random bytes read so about once in 2^40, and a token, a key or a sealed value never is.
     */
    static boolean isEcdsaSignature(String candidate) {
        byte[] der;
        try {
            der = java.util.Base64.getDecoder().decode(candidate);
        } catch (IllegalArgumentException notBase64) {
            return false;
        }
        if (der.length < 8 || der[0] != 0x30 || der[1] != der.length - 2 || der[2] != 0x02) {
            return false;
        }
        int rLength = der[3];
        if (rLength < 1 || rLength > 33 || 4 + rLength + 2 > der.length || der[4 + rLength] != 0x02) {
            return false;
        }
        int sLength = der[5 + rLength];
        return sLength >= 1 && sLength <= 33 && 6 + rLength + sLength == der.length;
    }

    /**
     * Mixed case and a digit: base64url of random bytes nearly always is, a 43-letter word never. "Nearly" was one
     * key in about 1,300 with no digit, which stayed literal where it was stored and failed the replay of whichever
     * run drew it — so base64's padding counts as the digit would: no word, path or name ends in {@code =}.
     */
    private static boolean looksRandom(String token) {
        boolean upper = false, lower = false, digit = token.endsWith("=");
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            upper |= Character.isUpperCase(c);
            lower |= Character.isLowerCase(c);
            digit |= Character.isDigit(c);
        }
        return upper && lower && digit;
    }

    private static String replace(String text, Pattern pattern, java.util.function.Function<Matcher, String> with) {
        Matcher matcher = pattern.matcher(text);
        if (!matcher.find()) {
            return text;
        }
        StringBuilder out = new StringBuilder(text.length());
        do {
            matcher.appendReplacement(out, Matcher.quoteReplacement(with.apply(matcher)));
        } while (matcher.find());
        matcher.appendTail(out);
        return out.toString();
    }

    /** The project's digest, BouncyCastle's, rather than whatever provider the JVM resolves. */
    static String sha256Hex(String value) {
        return Digests.sha256Hex(value);
    }
}
