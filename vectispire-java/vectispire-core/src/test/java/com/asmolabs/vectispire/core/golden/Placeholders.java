package com.asmolabs.vectispire.core.golden;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
    private static final Pattern ONE_TIME_CODE = Pattern.compile("\\d{6,8}");

    /** Integers counted from the epoch: the TOTP step a code was last accepted at. */
    private static final Set<String> CLOCK_COUNTERS = Set.of("totp_last_step", "totplaststep");

    /** A digest left once the known secrets' have been named: a chain link, a hash of something random. */
    private static final Pattern HEX_DIGEST = Pattern.compile("(?i)[0-9a-f]{32,128}");

    /** {@code RateWindows}' key, {@code <limit>:<window number>:<subject digest>}: the number is the clock's. */
    private static final Pattern RATE_WINDOW = Pattern.compile("^([A-Za-z0-9_-]+):\\d+:");

    /** API keys: {@code ApiKeys.generate()}'s shape. Their stored prefix is their first twelve characters. */
    private static final Pattern API_KEY = Pattern.compile("zsk_[A-Za-z0-9_-]{43}");
    private static final int API_KEY_PREFIX = 12;

    /** Thirty-two random bytes, base64url without padding: a session token, an agent key, a hand-off. */
    private static final Pattern RANDOM_TOKEN = Pattern.compile("(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])");

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
                || secrets.containsKey(value)) {
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

    /** The first pass: registers every credential a record carries, before any of it is rendered. */
    void collect(JsonNode node, String fieldName) {
        if (node == null) {
            return;
        }
        if (node.isObject()) {
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                collect(field.getValue(), field.getKey());
            }
        } else if (node.isArray()) {
            for (JsonNode element : node) {
                collect(element, fieldName);
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
            collectPatterns(text);
        }
    }

    /** Credentials recognised by their shape alone. */
    void collectPatterns(String raw) {
        // Not inside a stored form: an Argon2 hash or a sealed value is random, not a credential presented.
        String text = SEALED.matcher(PASSWORD_HASH.matcher(raw).replaceAll(" ")).replaceAll(" ");
        Matcher keys = API_KEY.matcher(text);
        while (keys.find()) {
            registerSecret(keys.group());
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
        // Stored forms first: an Argon2 hash carries 43 base64 characters that would otherwise read as a token.
        String out = replace(text, PASSWORD_HASH, match -> passwordHash(match.group()));
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
        return out;
    }

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

    /** Mixed case and a digit: base64url of random bytes nearly always is, a 43-letter word never. */
    private static boolean looksRandom(String token) {
        boolean upper = false, lower = false, digit = false;
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
