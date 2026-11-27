package com.asmolabs.vectispire.common.domain.threatintel;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;

/**
 * The threat-intelligence domain the Rust port ({@code cp-threatintel}) is held to, written to
 * {@code vectispire-rust/reference/threatintel/}: the CISA KEV catalogue read whole or refused, FIRST's EPSS file
 * streamed and refused for each way it can be not the whole file, the comparability rule, the risk matrix over a grid
 * of scores, and the two small readings — a CVE's shape and a stored feed state.
 *
 * <p><b>EPSS files are described, not stored.</b> A whole file has at least {@link EpssFile#MIN_ROWS} rows; each case
 * says how to build one — lines before, a count of generated rows, lines injected at given rows, lines after, and how
 * it is compressed — and both sides build the same bytes from it. What a read handed its sink is compared as the batch
 * sizes and a digest of every row, the scores written as {@code Double.toString} writes them.
 */
class ThreatIntelReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void theReferenceSet() throws IOException {
        ObjectNode out = JSON.createObjectNode();
        out.set("kev", kev());
        out.set("epss", epss());
        out.set("comparable", comparable());
        out.set("matrix", matrix());
        out.set("cves", cves());
        out.set("states", states());
        ReferenceSet.expect("threatintel/domain.json", JSON.writeValueAsString(out) + "\n");
    }

    // ── The KEV catalogue ──

    private static ArrayNode kev() throws IOException {
        List<String> documents = List.of(
                "{\"vulnerabilities\":[{\"cveID\":\"CVE-2021-44228\",\"dateAdded\":\"2021-12-10\"}]}",
                "{\"catalogVersion\":\"2026.11.18\",\"dateReleased\":\"2026-11-18T14:02:11.123Z\",\"count\":2,"
                        + "\"vulnerabilities\":[{\"cveID\":\" cve-2024-3094 \",\"dateAdded\":\"2024-03-29\"},"
                        + "{\"cveID\":\"CVE-2023-4966\",\"dateAdded\":\" 2023-10-18 \"}]}",
                "{\"vulnerabilities\":[]}",
                "{\"vulnerabilities\":{}}",
                "{\"data\":[]}",
                "[]",
                "{\"count\":3,\"vulnerabilities\":[{\"cveID\":\"CVE-2021-44228\"},{\"cveID\":\"CVE-2021-45046\"}]}",
                "{\"count\":2.0,\"vulnerabilities\":[{\"cveID\":\"CVE-2021-44228\"}]}",
                "{\"count\":\"9\",\"vulnerabilities\":[{\"cveID\":\"CVE-2021-44228\"}]}",
                "{\"count\":1,\"vulnerabilities\":[{\"cveID\":\"CVE-2021-44228\"},{\"cveID\":\"CVE-2021-44228\",\"dateAdded\":\"2022-01-01\"}]}",
                "{\"vulnerabilities\":[{\"cveID\":\"CVE-2021-1\"},{\"cveID\":\"GHSA-xxxx\"},{\"cveID\":12},{\"cve\":\"CVE-2021-44228\"}]}",
                "{\"vulnerabilities\":[{\"cveID\":\"CVE-2021-44228\",\"dateAdded\":\"2021-12-10\"},{\"cveID\":\"CVE-2021-1\"}],"
                        + "\"catalogVersion\":\"   \",\"dateReleased\":\"2026-11-18\"}",
                "{\"catalogVersion\":\"0123456789012345678901234567890123456789\",\"dateReleased\":\"2026-11-18T14:02:11+01:00\","
                        + "\"vulnerabilities\":[{\"cveID\":\"CVE-2024-0001\",\"dateAdded\":\"2024-02-29\"},"
                        + "{\"cveID\":\"CVE-2023-0001\",\"dateAdded\":\"2023-02-29\"},{\"cveID\":\"CVE-2023-0002\",\"dateAdded\":\"2023-2-01\"},"
                        + "{\"cveID\":\"CVE-2023-0003\",\"dateAdded\":20230101},{\"cveID\":\"CVE-2023-0004\",\"dateAdded\":\"+2023-01-01\"}]}",
                "{\"catalogVersion\":7,\"dateReleased\":\"2026-11-18t14:02:11z\",\"vulnerabilities\":[{\"cveID\":\"CVE-2024-0001\"}]}",
                "{\"dateReleased\":\"2026-11-18T14:02:60Z\",\"vulnerabilities\":[{\"cveID\":\"CVE-2024-0001\"}]}",
                "{\"dateReleased\":\"2026-11-18T14:02Z\",\"vulnerabilities\":[{\"cveID\":\"CVE-2024-0001\"}]}",
                "{\"dateReleased\":\"not a date\",\"vulnerabilities\":[{\"cveID\":\"CVE-2024-123456789\"}]}");
        ArrayNode cases = JSON.createArrayNode();
        for (String document : documents) {
            ObjectNode row = cases.addObject();
            row.put("document", document);
            try {
                KevCatalog catalog = KevCatalog.parse(JSON.readTree(document));
                ObjectNode read = row.putObject("catalog");
                read.put("version", catalog.version());
                read.put("released", catalog.released() == null ? null : catalog.released().toString());
                ArrayNode added = read.putArray("added");
                catalog.added().forEach((cve, day) -> added.addArray().add(cve).add(day == null ? null : day.toString()));
            } catch (KevCatalog.Unreadable refused) {
                row.put("unreadable", refused.getMessage());
            }
        }
        return cases;
    }

    // ── The EPSS file ──

    private static final String HEADER = "#model_version:v2025.03.14,score_date:2026-09-27T12:00:21Z";
    private static final String COLUMNS = "cve,epss,percentile";

    /** How a case's file is built; both sides build the same bytes from it. */
    private record Spec(
            String name,
            List<String> head,
            int rows,
            Map<Integer, String> inject,
            List<String> tail,
            String ending,
            String compression,
            int batch,
            boolean stop) {

        /**
         * The injected rows in row order. The cases write them with {@code Map.of}, whose iteration order is salted
         * per JVM run, and the spec is written to the reference set as it iterates: the file's bytes changed from one
         * run to the next and check mode failed at random.
         */
        Spec {
            inject = Collections.unmodifiableMap(new TreeMap<>(inject));
        }
    }

    private static List<Spec> specs() {
        int whole = (int) EpssFile.MIN_ROWS;
        List<String> standard = List.of(HEADER, COLUMNS);
        List<Spec> specs = new ArrayList<>();
        specs.add(new Spec("whole", standard, whole, Map.of(), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("whole, gzip", standard, whole + 3, Map.of(), List.of(""), "\n", "gzip", 7_777, false));
        specs.add(new Spec("whole, two gzip members", standard, whole, Map.of(), List.of(), "\n", "gzip-two-members", 50_000, false));
        specs.add(new Spec("crlf, blank lines", standard, whole, Map.of(10, "", 20, "   "), List.of(""), "\r\n", "none", 4_096, false));
        specs.add(new Spec("one row short", standard, whole - 1, Map.of(), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("stopped at the header", standard, whole, Map.of(), List.of(), "\n", "none", 5_000, true));
        specs.add(new Spec("empty", List.of(), 0, Map.of(), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("no header line", List.of(COLUMNS), whole, Map.of(), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("no model version", List.of("#score_date:2026-09-27T12:00:21Z", COLUMNS), whole, Map.of(), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("empty model version", List.of("#model_version:,score_date:2026-09-27", COLUMNS), 1, Map.of(), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("long model version", List.of("#model_version:v0123456789012345678901234567890123,score_date:2026-09-27", COLUMNS), 1, Map.of(), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("a day for a date", List.of("#model_version:v1,score_date:2026-09-27", COLUMNS), whole, Map.of(), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("an unreadable date", List.of("#model_version:v1,score_date:yesterday", COLUMNS), whole, Map.of(), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("an offset date", List.of("#model_version:v1,score_date:2026-09-27T12:00:21+02:00", COLUMNS), 1, Map.of(), List.of(), "\n", "none", 5_000, true));
        specs.add(new Spec("keys in another case, spaces, a field more", List.of("# MODEL_VERSION : v2 , Score_Date: 2026-09-27T00:00:00.5Z ,extra: x,orphan", COLUMNS), 1, Map.of(), List.of(), "\n", "none", 5_000, true));
        specs.add(new Spec("columns in another case", List.of(HEADER, " CVE,EPSS,Percentile "), 1, Map.of(), List.of(), "\n", "none", 5_000, true));
        specs.add(new Spec("not the columns", List.of(HEADER, "cve,score,percentile"), whole, Map.of(), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("no columns line", List.of(HEADER), 0, Map.of(), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("a short CVE", standard, whole, Map.of(50, "CVE-2020-1,0.1,0.1"), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("not a CVE", standard, whole, Map.of(7, "GHSA-2020-12345,0.1,0.1"), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("above one", standard, whole, Map.of(60_000, "CVE-2020-12345,1.5,0.1"), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("below zero", standard, whole, Map.of(3, "CVE-2020-12345,0.1,-0.0001"), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("not a number", standard, whole, Map.of(3, "CVE-2020-12345,abc,0.1"), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("empty field", standard, whole, Map.of(3, "CVE-2020-12345,,0.1"), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("NaN", standard, whole, Map.of(3, "CVE-2020-12345,NaN,0.1"), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("two fields", standard, whole, Map.of(3, "CVE-2020-12345,0.1"), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("four fields", standard, whole, Map.of(3, "CVE-2020-12345,0.1,0.2,"), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("Java's number spellings", standard, whole,
                Map.of(3, "cve-2020-12345, 0.1 ,0.2", 4, "CVE-2020-12346,1e-3,0.2d", 5, "CVE-2020-12347,0x1p-3,1",
                        6, "CVE-2020-12348,.5,5.e-1", 7, "CVE-2020-12349,+0.25,0.75F", 8, "CVE-2020-12350,-0,0.0"),
                List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("a line too long", standard, whole, Map.of(9, "CVE-2020-12345,0.1," + "1".repeat(300)), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("not ASCII", standard, whole, Map.of(9, "CVE-2020-12345,0.1,0.1é"), List.of(), "\n", "none", 5_000, false));
        specs.add(new Spec("gzip cut in its trailer", standard, whole, Map.of(), List.of(), "\n", "gzip-cut-4", 5_000, false));
        specs.add(new Spec("gzip cut in its data", standard, whole, Map.of(), List.of(), "\n", "gzip-cut-2000", 5_000, false));
        specs.add(new Spec("gzip with a wrong checksum", standard, whole, Map.of(), List.of(), "\n", "gzip-bad-crc", 5_000, false));
        return specs;
    }

    /** Row {@code i}: a CVE of one of twenty years, and two probabilities written with three decimals. */
    static String generated(int i) {
        return "CVE-" + (2000 + i % 20) + "-" + String.format("%05d", i) + ",0." + String.format("%03d", i % 1000) + ",0."
                + String.format("%03d", (i * 7) % 1000);
    }

    static byte[] build(Spec spec) throws IOException {
        StringBuilder text = new StringBuilder();
        for (String line : spec.head()) {
            text.append(line).append(spec.ending());
        }
        for (int i = 0; i < spec.rows(); i++) {
            String injected = spec.inject().get(i);
            if (injected != null) {
                text.append(injected).append(spec.ending());
            }
            text.append(generated(i)).append(spec.ending());
        }
        for (String line : spec.tail()) {
            text.append(line).append(spec.ending());
        }
        byte[] plain = text.toString().getBytes(StandardCharsets.UTF_8);
        return switch (spec.compression()) {
            case "none" -> plain;
            case "gzip" -> gzip(plain);
            case "gzip-two-members" -> {
                int half = plain.length / 2;
                ByteArrayOutputStream both = new ByteArrayOutputStream();
                both.write(gzip(Arrays.copyOfRange(plain, 0, half)));
                both.write(gzip(Arrays.copyOfRange(plain, half, plain.length)));
                yield both.toByteArray();
            }
            case "gzip-cut-4" -> cut(gzip(plain), 4);
            case "gzip-cut-2000" -> cut(gzip(plain), 2_000);
            case "gzip-bad-crc" -> {
                byte[] archive = gzip(plain);
                archive[archive.length - 8] ^= 0x5a;
                yield archive;
            }
            default -> throw new IllegalArgumentException(spec.compression());
        };
    }

    private static byte[] gzip(byte[] plain) throws IOException {
        ByteArrayOutputStream archive = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(archive)) {
            out.write(plain);
        }
        return archive.toByteArray();
    }

    private static byte[] cut(byte[] bytes, int by) {
        return Arrays.copyOf(bytes, bytes.length - by);
    }

    private static ArrayNode epss() throws IOException {
        ArrayNode cases = JSON.createArrayNode();
        for (Spec spec : specs()) {
            ObjectNode row = cases.addObject();
            row.set("spec", JSON.valueToTree(spec));
            List<Integer> batches = new ArrayList<>();
            MessageDigest digest = sha256();
            EpssFile.Sink sink = new EpssFile.Sink() {
                @Override
                public boolean header(EpssFile.Header header) {
                    return !spec.stop();
                }

                @Override
                public void batch(List<EpssFile.Score> scores) {
                    batches.add(scores.size());
                    for (EpssFile.Score score : scores) {
                        digest.update((score.cve() + "," + score.score() + "," + score.percentile() + "\n")
                                .getBytes(StandardCharsets.UTF_8));
                    }
                }
            };
            byte[] bytes = build(spec);
            row.put("bytes", HexFormat.of().formatHex(sha256().digest(bytes)));
            try {
                EpssFile.Read read = EpssFile.read(new ByteArrayInputStream(bytes), spec.batch(), sink);
                ObjectNode answer = row.putObject("read");
                answer.put("modelVersion", read.header().modelVersion());
                answer.put("scoreDate", read.header().scoreDate().toString());
                answer.put("rows", read.rows());
                answer.put("stopped", read.stopped());
            } catch (EpssFile.Unreadable refused) {
                row.put("unreadable", refused.getMessage());
            }
            ArrayNode sizes = row.putArray("batches");
            batches.forEach(sizes::add);
            row.put("digest", HexFormat.of().formatHex(digest.digest()));
        }
        return cases;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static ArrayNode comparable() {
        ArrayNode cases = JSON.createArrayNode();
        long[][] pairs = {{0, 5}, {100, 90}, {100, 89}, {1_000_000, 900_000}, {1_000_000, 899_999}, {10, 9}, {7, 6}, {3, 3}};
        for (long[] pair : pairs) {
            ArrayNode row = cases.addArray().add(pair[0]).add(pair[1]);
            try {
                EpssFile.requireComparable(pair[0], pair[1]);
                row.addNull();
            } catch (EpssFile.Unreadable refused) {
                row.add(refused.getMessage());
            }
        }
        return cases;
    }

    // ── The ranking ──

    private static ArrayNode matrix() {
        Double[] cvss = {null, 0.0, 2.5, 4.9, 5.0, 6.95, 6.99, 7.0, 7.05, 8.3, 9.8, 10.0, 12.0, -1.0};
        Double[] epss = {null, 0.0, 0.0099, 0.01, 0.0125, 0.049, 0.05, 0.1999, 0.2, 0.4999, 0.5, 0.75, 1.0, 1.5};
        ArrayNode cases = JSON.createArrayNode();
        for (Double c : cvss) {
            for (Double e : epss) {
                for (boolean kev : new boolean[] {false, true}) {
                    String tier = EpssRiskMatrix.determineTier(c, e, kev);
                    cases.addArray()
                            .add(c)
                            .add(e)
                            .add(kev)
                            .add(EpssRiskMatrix.calculatePriorityScore(c, e, kev))
                            .add(tier)
                            .add(EpssRiskMatrix.determineAction(tier, kev).name());
                }
            }
        }
        for (String tier : List.of("CRITICAL_ARMED", "HIGH_PROBABLE", "MEDIUM_THEORETICAL", "LOW_PROBABILITY", "OTHER")) {
            for (boolean kev : new boolean[] {false, true}) {
                cases.addArray().addNull().addNull().add(kev).addNull().add(tier)
                        .add(EpssRiskMatrix.determineAction(tier, kev).name());
            }
        }
        return cases;
    }

    private static ArrayNode cves() {
        ArrayNode cases = JSON.createArrayNode();
        for (String identifier : Arrays.asList(null, "", "CVE-2021-44228", " cve-2021-44228 ", "CVE-2021-1234", "CVE-2021-123",
                "CVE-21-44228", "CVE-2021-44228a", "GHSA-jfh8-c2jp-5v3q", "CVE-２０２１-44228", " CVE-2021-44228")) {
            cases.addArray().add(identifier).add(Exploitation.namesACve(identifier));
        }
        return cases;
    }

    private static ArrayNode states() {
        ArrayNode cases = JSON.createArrayNode();
        for (String stored : Arrays.asList(null, "NEVER_SYNCED", "SYNCED", "FAILED", "synced", "", "RUNNING")) {
            cases.addArray().add(stored).add(ThreatIntelSyncStatus.State.of(stored).name());
        }
        return cases;
    }

}
