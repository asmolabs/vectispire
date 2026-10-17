package com.asmolabs.vectispire.common.domain.issues;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.SplittableRandom;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

/**
 * What an issue's fingerprint, its tool keys and {@link BoundedText#clip} answer — the answers the Rust
 * control plane's {@code fingerprint}, {@code tool_keys} and {@code bounded_text} are held to, with no
 * tolerance.
 *
 * <p><b>Why this set exists before the Rust code.</b> A fingerprint that drifts fails nowhere: the next scan
 * resolves the whole backlog and recreates it, triage lost (AGENTS.md). The places where two languages
 * disagree are not in the formula but in the Java behaviours under it, and each is a case below:
 * {@code getBytes(UTF_8)} writes an unpaired surrogate as {@code ?}; {@code String.strip()} asks
 * {@code Character.isWhitespace}, which leaves the no-break spaces and U+0085 alone and strips U+001C–U+001F,
 * the opposite of Rust's {@code char::is_whitespace} on each; {@code toLowerCase(Locale.ROOT)}; a null field
 * hashed as empty; an empty purl falling back to the package name; lengths in UTF-16 units.
 *
 * <p><b>Two files.</b> {@code cases.json} is chosen by hand — {@code IssueFingerprintTest}'s and
 * {@code ToolFingerprintTest}'s cases, then each quirk. {@code corpus.json} is generated from a fixed seed over
 * an alphabet made of those same quirks, so that their combinations are hashed by both sides too; the seed
 * makes check mode meaningful, since the same run regenerates the same inputs.
 *
 * <p><b>A text is a JSON string, or {@code {"utf16": [units]}}</b> when it holds an unpaired surrogate: this
 * file is written as UTF-8, which cannot carry one (it would arrive as the very {@code ?} under test), and the
 * Rust reader refuses one in a JSON escape.
 */
class FingerprintReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private static final ScanTarget REPO = new ScanTarget.Repository(3);

    @Test
    void theHandPickedCases() throws Exception {
        ArrayNode cases = JSON.createArrayNode();

        // IssueFingerprintTest
        of(cases, "pinned", REPO, FindingType.VULNERABILITY, "CVE-2024-1234", "pkg:pypi/requests@2.31.0", "requests", "requirements.txt");
        of(cases, "upgraded purl", REPO, FindingType.VULNERABILITY, "CVE-2024-1234", "pkg:pypi/requests@2.32.0", "requests", "requirements.txt");
        of(cases, "empty purl", REPO, FindingType.VULNERABILITY, "CVE-2024-1234", "", "requests", null);
        of(cases, "null purl", REPO, FindingType.VULNERABILITY, "CVE-2024-1234", null, "requests", null);
        of(cases, "container target", new ScanTarget.Container(3), FindingType.VULNERABILITY, "CVE-2024-1234", "pkg:pypi/requests@2.31.0", "requests", "requirements.txt");
        of(cases, "repository zero", new ScanTarget.Repository(0), FindingType.SECRET, "aws-key", null, null, "app.py");
        of(cases, "container zero", new ScanTarget.Container(0), FindingType.SECRET, "aws-key", null, null, "app.py");
        of(cases, "purl wins over the name", REPO, FindingType.VULNERABILITY, "CVE-2024-1234", "pkg:pypi/requests@2.31.0", "other-name", "requirements.txt");
        of(cases, "bar in the name", REPO, FindingType.SAST, "rule.a", null, "pkg|b", "c.py");
        of(cases, "bar moved to the path", REPO, FindingType.SAST, "rule.a", null, "pkg", "b/c.py");

        // Null joined as empty, field by field, and an empty purl with an empty name.
        of(cases, "every optional field null", REPO, FindingType.IAC, null, null, null, null);
        of(cases, "every optional field empty", REPO, FindingType.IAC, "", "", "", "");
        of(cases, "empty purl and null name", REPO, FindingType.LICENSE, "MIT", "", null, "pom.xml");
        of(cases, "whitespace purl is not empty", REPO, FindingType.LICENSE, "MIT", " ", "name", "pom.xml");
        of(cases, "negative id", new ScanTarget.Repository(-7), FindingType.EOL, "eol", null, "debian", null);
        of(cases, "largest id", new ScanTarget.Container(Long.MAX_VALUE), FindingType.QUALITY, "q", null, null, null);
        of(cases, "smallest id", new ScanTarget.Repository(Long.MIN_VALUE), FindingType.AI_REVIEW, "a", null, null, null);
        for (FindingType type : FindingType.values()) {
            of(cases, "type " + type.wireName(), REPO, type, "id", null, "pkg", "path");
        }

        // getBytes(UTF_8): an unpaired surrogate is one '?'; a pair is one four-byte character.
        of(cases, "lone high surrogate in the identifier", REPO, FindingType.SECRET, "key\uD83D", null, null, "a");
        of(cases, "lone low surrogate in the path", REPO, FindingType.SECRET, "key", null, null, "\uDE00.txt");
        of(cases, "reversed pair", REPO, FindingType.SECRET, "\uDE00\uD83D", null, null, null);
        of(cases, "the question mark itself", REPO, FindingType.SECRET, "key?", null, null, "a");
        of(cases, "an astral character", REPO, FindingType.SAST, "rule", null, "😀", "src/😀.py");
        of(cases, "lone surrogate in the purl", REPO, FindingType.VULNERABILITY, "CVE", "pkg:npm/\uDBFF", "name", null);
        of(cases, "NUL inside a field", REPO, FindingType.SAST, "a\u0000b", null, null, null);
        of(cases, "non-ASCII path", REPO, FindingType.IAC, "CKV_1", null, null, "répertoire/naïve ΣΑΣ.tf");
        of(cases, "no-break space kept", REPO, FindingType.SECRET, " key ", null, null, " p");

        // ToolFingerprintTest
        ofTool(cases, "plugin formula", REPO, FindingType.PLUGIN, () -> ToolKeys.plugin("acme-lint"), "ACME001", "src/a.py");
        ofTool(cases, "plugin renamed", REPO, FindingType.PLUGIN, () -> ToolKeys.plugin("acme-lint-2"), "ACME001", "src/a.py");
        ofTool(cases, "plugin rule renamed", REPO, FindingType.PLUGIN, () -> ToolKeys.plugin("acme-lint"), "ACME002", "src/a.py");
        ofTool(cases, "plugin file moved", REPO, FindingType.PLUGIN, () -> ToolKeys.plugin("acme-lint"), "ACME001", "src/b.py");
        ofTool(cases, "imported, same tool name", REPO, FindingType.IMPORTED, () -> ToolKeys.imported("ci", "acme-lint"), "ACME001", "src/a.py");
        ofTool(cases, "blank key", REPO, FindingType.PLUGIN, () -> " ", "r", "f");
        ofTool(cases, "empty key", REPO, FindingType.IMPORTED, () -> "", "r", "f");
        ofTool(cases, "null key", REPO, FindingType.PLUGIN, () -> null, "r", "f");
        ofTool(cases, "key of no-break spaces is not blank", REPO, FindingType.PLUGIN, () -> "  ", "r", "f");
        ofTool(cases, "key of U+001C is blank", REPO, FindingType.PLUGIN, () -> "\u001C\u001F", "r", "f");
        ofTool(cases, "key of U+0085 is not blank", REPO, FindingType.IMPORTED, () -> "\u0085", "r", "f");
        ofTool(cases, "key of ideographic space is blank", REPO, FindingType.IMPORTED, () -> "　 ", "r", "f");
        ofTool(cases, "not tool-scoped", REPO, FindingType.SAST, () -> "plugin:x", "r", "f");
        ofTool(cases, "not tool-scoped, and blank", REPO, FindingType.SECRET, () -> " ", "r", "f");
        ofTool(cases, "null rule and path", REPO, FindingType.PLUGIN, () -> "plugin:x", null, null);

        plugin(cases, "plugin id", "acme-lint");
        plugin(cases, "plugin id stripped", " acme-lint\t");
        plugin(cases, "plugin id keeps its case", "ACME");
        plugin(cases, "plugin id null", null);
        plugin(cases, "plugin id blank", " \n ");
        plugin(cases, "plugin id of no-break spaces", " ");
        plugin(cases, "plugin id keeps no-break spaces", " acme ");
        plugin(cases, "plugin id keeps U+0085", "\u0085acme\u0085");
        plugin(cases, "plugin id strips U+001C to U+001F", "\u001Cacme\u001F");
        plugin(cases, "plugin id strips U+2000 and U+3000", " acme　");
        plugin(cases, "plugin id keeps U+180E and U+200B", "᠎acme​");
        plugin(cases, "plugin id with a lone surrogate", "\uD800acme");
        imported(cases, "imported", "ci-main", " ESLint ");
        imported(cases, "imported lower", "ci-main", "eslint");
        imported(cases, "imported upper", "ci-main", "ESLINT");
        imported(cases, "source keeps its case", "CI-Main", "x");
        imported(cases, "source null", null, "x");
        imported(cases, "tool null", "ci", null);
        imported(cases, "tool blank", "ci", "\t");
        imported(cases, "both blank: the source is named", " ", " ");
        imported(cases, "dotted capital I", "ci", "İSTANBUL");
        imported(cases, "dotless i stays", "ci", "ı");
        imported(cases, "final sigma", "ci", "ΟΔΟΣ ΣΑΣ.Σ");
        imported(cases, "sigma alone", "ci", "Σ");
        imported(cases, "Kelvin sign", "ci", "K");
        imported(cases, "sharp s stays", "ci", "Straße");
        imported(cases, "title case digraph", "ci", "ǅ");
        imported(cases, "astral capital", "ci", "𐐀");
        imported(cases, "tool with a lone surrogate", "ci", "A\uDC00B");
        imported(cases, "tool stripped of no-break spaces? no", "ci", " Tool ");

        fields(cases, "no field");
        fields(cases, "one empty field", "");
        fields(cases, "one null field", (String) null);
        fields(cases, "two null fields", null, null);
        fields(cases, "fields with a NUL", "a\u0000", "b");
        fields(cases, "fields shifted", "a", "\u0000b");

        for (String text : new String[] {"", "abc", "é", "€", "😀", "\uD83D", "\uDE00", "\uDE00\uD83D", "a\uD83Db", "\u0000"}) {
            ObjectNode c = cases.addObject();
            c.put("name", "utf-8 of " + HexFormat.of().formatHex(text.getBytes(StandardCharsets.UTF_16BE)));
            c.put("op", "utf8");
            c.set("text", text(text));
            c.put("bytes", HexFormat.of().formatHex(text.getBytes(StandardCharsets.UTF_8)));
        }

        clip(cases, "null stays null", null, 3);
        clip(cases, "shorter", "abc", 5);
        clip(cases, "exact", "abc", 3);
        clip(cases, "cut", "abcdef", 3);
        clip(cases, "to zero", "abc", 0);
        clip(cases, "empty to zero", "", 0);
        clip(cases, "astral fits exactly", "ab😀", 4);
        clip(cases, "astral at the boundary is dropped whole", "ab😀c", 3);
        clip(cases, "astral after the boundary", "ab😀c", 2);
        clip(cases, "astral first, max one", "😀x", 1);
        clip(cases, "two astral, max three", "😀😁", 3);
        clip(cases, "astral counts two", "😀", 1);
        clip(cases, "BMP non-ASCII counts one", "ééé", 2);
        clip(cases, "combining mark is cut", "éé", 3);

        tooLong(cases, "fits", "abc", 3);
        tooLong(cases, "too long", "abcd", 3);
        tooLong(cases, "astral is two units", "😀😀", 3);
        tooLong(cases, "null fits", null, 0);

        ReferenceSet.expect("fingerprints/cases.json", JSON.writeValueAsString(cases) + "\n");
    }

    /**
     * A seeded corpus over the quirks' alphabet. Ten units chosen to break a port (the surrogates, the
     * spaces Java and Rust disagree on, the case-mapping traps), the rest plain, so that a generated field
     * is mostly ordinary and sometimes not — as a scanner's output is.
     */
    @Test
    void theGeneratedCorpus() throws Exception {
        SplittableRandom random = new SplittableRandom(0x2_4_F1_96_E7_A1L);
        ArrayNode corpus = JSON.createArrayNode();
        for (int i = 0; i < 1000; i++) {
            ObjectNode c = corpus.addObject();
            ScanTarget target = random.nextBoolean()
                    ? new ScanTarget.Repository(id(random))
                    : new ScanTarget.Container(id(random));
            FindingType type = FindingType.values()[random.nextInt(FindingType.values().length)];
            String identifier = field(random);
            String purl = field(random);
            String name = field(random);
            String path = field(random);
            c.set("target", target(target));
            c.put("type", type.wireName());
            c.set("identifier", text(identifier));
            c.set("purl", text(purl));
            c.set("package_name", text(name));
            c.set("file_path", text(path));
            c.put("fingerprint", IssueFingerprint.of(new IssueFingerprint.Input(target, type, identifier, purl, name, path)));
            c.set("plugin_key", answer(() -> ToolKeys.plugin(name)));
            c.set("imported_key", answer(() -> ToolKeys.imported(purl, name)));
            c.set("tool_fingerprint", answer(() -> IssueFingerprint.ofTool(target, type, purl, identifier, path)));
            int max = random.nextInt(12);
            // Clipping a lone surrogate is left out: a Rust string cannot hold one (see the crate README).
            if (path != null && wellFormed(path)) {
                c.put("clip_max", max);
                c.set("clipped", text(BoundedText.clip(path, max)));
            }
        }
        ReferenceSet.expect("fingerprints/corpus.json", JSON.writeValueAsString(corpus) + "\n");
    }

    /**
     * {@code toLowerCase(Locale.ROOT)} around the capital sigma, the one character the root locale lowers by
     * context — and Java decides that context with its word {@code BreakIterator}, where Unicode (and Rust's
     * {@code to_lowercase}) skip case-ignorable characters: "ΣΣ-ı" keeps two medial sigmas in Java and ends on
     * a final one in Rust. An imported tool's name is lowered into its key, so this is fingerprint material.
     * The alphabet holds one character of each class the word rules tell apart.
     */
    @Test
    void theSigmaCorpus() throws Exception {
        String[] alphabet = {"\u03A3", "\u03A3", "\u03A3", "\u0391", "\u03B1", "A", "a", "1", "-", ".", "'", "\"", "_", ",",
            " ", ":", "\u00B7", "\u2019", "\u00AD", "\u200B", "\u0301", "\u0903", "\u0E01", "\u3042", "\u30A2", "\u4E00",
            "$", "#", "%", "\t", "\n", "\u00B2", "\u2160", "\u0964", "\u2010", "\u2027", "\u066B", "\u00A2", "\u02B0",
            "\u01C5", "\u0130", "\u0131"};
        SplittableRandom random = new SplittableRandom(0x5167A);
        ArrayNode corpus = JSON.createArrayNode();
        for (int i = 0; i < 3000; i++) {
            StringBuilder text = new StringBuilder();
            int length = 1 + random.nextInt(7);
            for (int j = 0; j < length; j++) {
                text.append(alphabet[random.nextInt(alphabet.length)]);
            }
            String value = text.toString();
            corpus.addObject().put("text", value).put("lower", value.toLowerCase(java.util.Locale.ROOT));
        }
        ReferenceSet.expect("fingerprints/lowercase.json", JSON.writeValueAsString(corpus) + "\n");
    }

    private static final String[] ALPHABET = {
        "a", "b", "Z", "0", "/", ".", "-", ":", "@", "|", "?", " ", "\t", "\u0000",
        " ", " ", " ", "\u0085", "\u001C", "\u001F", " ", "　", " ", "᠎", "​",
        "😀", "𐐀", "\uD83D", "\uDE00", "\uDBFF",
        "é", "É", "Σ", "İ", "ı", "K", "ß", "ǅ", "ﬀ", "́", "€"
    };

    private static String field(SplittableRandom random) {
        int roll = random.nextInt(10);
        if (roll == 0) {
            return null;
        }
        if (roll == 1) {
            return "";
        }
        StringBuilder text = new StringBuilder();
        int length = 1 + random.nextInt(8);
        for (int i = 0; i < length; i++) {
            text.append(ALPHABET[random.nextInt(ALPHABET.length)]);
        }
        return text.toString();
    }

    private static long id(SplittableRandom random) {
        return switch (random.nextInt(6)) {
            case 0 -> 0;
            case 1 -> Long.MAX_VALUE;
            case 2 -> Long.MIN_VALUE;
            case 3 -> -random.nextInt(1000);
            default -> random.nextInt(100_000);
        };
    }

    private static void of(ArrayNode cases, String name, ScanTarget target, FindingType type, String identifier,
            String purl, String packageName, String filePath) {
        ObjectNode c = cases.addObject();
        c.put("name", name);
        c.put("op", "of");
        c.set("target", target(target));
        c.put("type", type.wireName());
        c.set("identifier", text(identifier));
        c.set("purl", text(purl));
        c.set("package_name", text(packageName));
        c.set("file_path", text(filePath));
        c.put("fingerprint", IssueFingerprint.of(new IssueFingerprint.Input(target, type, identifier, purl, packageName, filePath)));
    }

    private static void ofTool(ArrayNode cases, String name, ScanTarget target, FindingType type, Supplier<String> toolKey,
            String ruleId, String filePath) {
        ObjectNode c = cases.addObject();
        c.put("name", name);
        c.put("op", "of_tool");
        c.set("target", target(target));
        c.put("type", type.wireName());
        c.set("tool_key", text(toolKey.get()));
        c.set("rule_id", text(ruleId));
        c.set("file_path", text(filePath));
        c.set("answer", answer(() -> IssueFingerprint.ofTool(target, type, toolKey.get(), ruleId, filePath)));
    }

    private static void plugin(ArrayNode cases, String name, String id) {
        ObjectNode c = cases.addObject();
        c.put("name", name);
        c.put("op", "plugin_key");
        c.set("id", text(id));
        c.set("answer", answer(() -> ToolKeys.plugin(id)));
    }

    private static void imported(ArrayNode cases, String name, String source, String tool) {
        ObjectNode c = cases.addObject();
        c.put("name", name);
        c.put("op", "imported_key");
        c.set("source", text(source));
        c.set("tool", text(tool));
        c.set("answer", answer(() -> ToolKeys.imported(source, tool)));
    }

    private static void fields(ArrayNode cases, String name, String... fields) {
        ObjectNode c = cases.addObject();
        c.put("name", name);
        c.put("op", "fields");
        ArrayNode list = c.putArray("fields");
        for (String field : fields) {
            list.add(text(field));
        }
        c.put("hash", Digests.sha256Fields(fields));
    }

    private static void clip(ArrayNode cases, String name, String value, int max) {
        ObjectNode c = cases.addObject();
        c.put("name", name);
        c.put("op", "clip");
        c.set("value", text(value));
        c.put("max", max);
        c.set("clipped", text(BoundedText.clip(value, max)));
    }

    private static void tooLong(ArrayNode cases, String name, String value, int max) {
        ObjectNode c = cases.addObject();
        c.put("name", name);
        c.put("op", "too_long");
        c.set("value", text(value));
        c.put("max", max);
        c.put("message", BoundedText.tooLong(value, max, "The comment").orElse(null));
    }

    /** {@code {"value": …}} or {@code {"refused": message}}: the refusal's sentence is part of the answer. */
    private static JsonNode answer(Supplier<String> call) {
        ObjectNode answer = NODES.objectNode();
        try {
            answer.set("value", text(call.get()));
        } catch (IllegalArgumentException refused) {
            answer.put("refused", refused.getMessage());
        }
        return answer;
    }

    private static JsonNode target(ScanTarget target) {
        ObjectNode node = NODES.objectNode();
        switch (target) {
            case ScanTarget.Repository r -> node.put("repository", r.id());
            case ScanTarget.Container c -> node.put("container", c.id());
        }
        return node;
    }

    static JsonNode text(String value) {
        if (value == null) {
            return NODES.nullNode();
        }
        if (wellFormed(value)) {
            return NODES.textNode(value);
        }
        ObjectNode units = NODES.objectNode();
        ArrayNode list = units.putArray("utf16");
        for (int i = 0; i < value.length(); i++) {
            list.add((int) value.charAt(i));
        }
        return units;
    }

    private static boolean wellFormed(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < value.length() && Character.isLowSurrogate(value.charAt(i + 1))) {
                i++;
            } else if (Character.isSurrogate(c)) {
                return false;
            }
        }
        return true;
    }
}
