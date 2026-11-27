package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Fixed Syft and Grype outputs in, what the agent sends out — byte for byte as its JSON mapper writes
 * it — for the Rust port's dependency parsers to match (see {@code ReferenceSet}).
 *
 * <p><b>The findings feed the issue fingerprint.</b> The identifier, the package and its installed
 * version are what an issue is recognised by; a parser that reads one differently resolves every
 * dependency issue of a target and recreates it, its triage lost.
 *
 * <p>Each output goes through what the scanner does with a container's standard output — {@code
 * ContainerRunner.parseJson}, then {@code findings} for the matcher — so the absent cases (nothing
 * printed, not JSON) are pinned as {@code null} alongside the findings, and a report of another shape,
 * which fails the step, as {@code {"failure": <the sentence>}}. The first three of each
 * directory are real outputs of the pinned images on small fixture repositories and an exported
 * image; the rest are the edge cases a real run does not produce.
 *
 * <p>The mapper is built as {@code VectispireAgentApplication} builds it, as in {@code
 * SecretsReferenceSetTest}.
 */
class DependenciesReferenceSetTest {

    private static final ObjectMapper WIRE = JsonMapper.builder()
            .addModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
            .addModule(new com.fasterxml.jackson.datatype.jdk8.Jdk8Module())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private static List<Path> inputs(String directory) throws Exception {
        try (Stream<Path> listed = Files.list(ReferenceSet.resolve(directory))) {
            return listed.filter(path -> path.toString().endsWith(".json")).sorted().toList();
        }
    }

    private static ContainerRunner.ContainerResult printed(Path output) throws Exception {
        return new ContainerRunner.ContainerResult(Files.readString(output, StandardCharsets.UTF_8), "", 0);
    }

    @Test
    void theFindingsTheRustPortIsHeldTo() throws Exception {
        for (Path output : inputs("dependencies/matches")) {
            String answer;
            try {
                var findings = ContainerRunner.parseJson(printed(output), "grype (SBOM analysis)", List.of(0))
                        .map(DependencyScanner::findings);
                answer = WIRE.writeValueAsString(findings);
            } catch (ScannerFailureException failed) {
                // A report of another shape fails the step (decision 0007): pinned as the sentence the
                // scan carries, in an object no findings list can be mistaken for.
                answer = WIRE.writeValueAsString(java.util.Map.of("failure", failed.getMessage()));
            }
            ReferenceSet.expect("dependencies/findings/" + output.getFileName(), answer + "\n");
        }
    }

    @Test
    void theSbomsTheRustPortIsHeldTo() throws Exception {
        for (Path output : inputs("dependencies/sboms")) {
            var sbom = ContainerRunner.parseJson(printed(output), "syft (directory SBOM)", List.of(0));
            ReferenceSet.expect("dependencies/sbom/" + output.getFileName(), WIRE.writeValueAsString(sbom) + "\n");
        }
    }

    /**
     * The {@code checked} file of a shared database cache, as {@code Instant.toString} writes it — read
     * by a Rust agent on the same cache, and the Rust agent's read by this side's {@code Instant.parse}.
     */
    @Test
    void theCheckTimesBothAgentsReadOnASharedCache() throws Exception {
        StringBuilder written = new StringBuilder();
        for (Instant at : List.of(
                Instant.parse("2026-09-27T10:00:00Z"),
                Instant.ofEpochSecond(1_792_174_740L, 123_000_000),
                Instant.ofEpochSecond(1_709_251_199L, 1_000),
                Instant.ofEpochSecond(1_792_174_740L, 7),
                Instant.EPOCH)) {
            written.append(at.getEpochSecond()).append(' ').append(at.getNano()).append(' ').append(at).append('\n');
        }
        ReferenceSet.expect("dependencies/database/instants.txt", written.toString());
    }

    /** {@code db check}'s answer on the pinned matcher, measured on the real database on 2026-11-27. */
    private static final String CHECK_CURRENT = """
            {
             "currentDB": {
              "schemaVersion": "v6.1.10",
              "built": "2026-11-27T06:22:11Z"
             },
             "candidateDB": null,
             "updateAvailable": false
            }
            """;

    private static final String CHECK_NO_CURRENT = """
            {
             "currentDB": null,
             "candidateDB": {
              "schemaVersion": "v6.1.10",
              "built": "2026-11-27T06:22:11Z",
              "path": "vulnerability-db_v6.1.10_2026-11-27T00:21:50Z_1795760531.tar.zst",
              "checksum": "sha256:b1f986487adf96493a3f0f2a11c1617ceb00f2a78fa3ee1a7ddbb42c2eb001cf"
             },
             "updateAvailable": true
            }
            """;

    private static final String STATUS_VALID = """
            {
             "schemaVersion": "v6.1.10",
             "built": "2026-11-27T06:22:11Z",
             "path": "/cache/6/vulnerability.db",
             "valid": true
            }
            """;

    private static final String STATUS_BAD_CHECKSUM = """
            {
             "schemaVersion": "v6.1.10",
             "built": "2026-11-27T06:22:11Z",
             "path": "/cache/6/vulnerability.db",
             "valid": false,
             "error": "bad db checksum (/cache/6/vulnerability.db): \\"xxh64:0000000000000000\\" vs \\"xxh64:488123242339ea99\\""
            }
            """;

    private static final String STATUS_TRUNCATED = """
            {
             "schemaVersion": "",
             "path": "/cache/6/vulnerability.db",
             "valid": false,
             "error": "failed to read DB description: failed to open db: unable to connect to DB: database disk image is malformed (11)"
            }
            """;

    private record Answer(String name, ContainerRunner.ContainerResult result) {}

    private static Answer ran(String name, int exitCode, String stdout) {
        return new Answer(name, new ContainerRunner.ContainerResult(stdout, "", exitCode));
    }

    private static java.util.Map<String, Object> asked(Answer answer, String verdictName, Object verdict) {
        var row = new java.util.LinkedHashMap<String, Object>();
        row.put("name", answer.name());
        row.put("ran", answer.result() != null);
        row.put("exitCode", answer.result() == null ? null : answer.result().exitCode());
        row.put("stdout", answer.result() == null ? null : answer.result().stdout());
        row.put(verdictName, verdict.toString());
        return row;
    }

    /**
     * What becomes of a published copy of the matcher's database, decided by both agents on one cache: the
     * check's answer read, the read-back's, and the decision they make together. The first answers of each
     * are the pinned matcher's on the real database — a copy whose checksum no longer matches is "current"
     * to the check and refused by the read-back, one cut short has no current database for the check and is
     * refused too, and the check without the network exits 1 with nothing on its standard output.
     */
    @Test
    void theDatabaseDecisionsBothAgentsMakeOnASharedCache() throws Exception {
        var checks = new java.util.ArrayList<Object>();
        for (Answer answer : List.of(
                ran("real: a current copy, or one whose checksum no longer matches", 0, CHECK_CURRENT),
                ran("real: a copy cut short, no current database", 100, CHECK_NO_CURRENT),
                ran("real: no network", 1, ""),
                ran("exit 100 with nothing printed", 100, ""),
                ran("exit 0, an update available", 0, "{\"updateAvailable\": true}"),
                ran("exit 0, the answer not a boolean", 0, "{\"updateAvailable\": \"true\"}"),
                ran("exit 0, not JSON", 0, "update available"),
                ran("exit 0, nothing printed", 0, ""),
                ran("exit 1, an answer printed", 1, "{\"updateAvailable\": false}"),
                ran("exit 2, an update available printed", 2, "{\"updateAvailable\": true}"),
                new Answer("the matcher could not be run", null))) {
            checks.add(asked(answer, "freshness", VulnerabilityDatabase.freshness(answer.result())));
        }
        var readBacks = new java.util.ArrayList<Object>();
        for (Answer answer : List.of(
                ran("real: a whole copy", 0, STATUS_VALID),
                ran("real: a checksum that no longer matches", 1, STATUS_BAD_CHECKSUM),
                ran("real: a copy cut short", 1, STATUS_TRUNCATED),
                ran("exit 0, not valid", 0, "{\"valid\": false}"),
                ran("exit 1, valid", 1, "{\"valid\": true}"),
                ran("exit 0, not JSON", 0, "valid"),
                ran("exit 0, nothing printed", 0, ""),
                ran("exit 0, the verdict as text", 0, "{\"valid\": \" true \"}"),
                ran("exit 0, the verdict as another text", 0, "{\"valid\": \"yes\"}"),
                ran("exit 0, the verdict as a number", 0, "{\"valid\": 1}"),
                ran("exit 0, the verdict as zero", 0, "{\"valid\": 0}"),
                ran("exit 0, no verdict", 0, "{\"schemaVersion\": \"v6.1.10\"}"),
                ran("killed", 137, ""),
                new Answer("the matcher could not be run", null))) {
            readBacks.add(asked(answer, "usability", VulnerabilityDatabase.usability(answer.result())));
        }
        var decisions = new java.util.ArrayList<Object>();
        for (VulnerabilityDatabase.Usability usability : VulnerabilityDatabase.Usability.values()) {
            for (VulnerabilityDatabase.Freshness freshness : VulnerabilityDatabase.Freshness.values()) {
                var row = new java.util.LinkedHashMap<String, Object>();
                row.put("usability", usability.toString());
                row.put("freshness", freshness.toString());
                row.put("decision", VulnerabilityDatabase.decide(usability, freshness).toString());
                decisions.add(row);
            }
        }
        var set = new java.util.LinkedHashMap<String, Object>();
        set.put("checks", checks);
        set.put("readBacks", readBacks);
        set.put("decisions", decisions);
        ReferenceSet.expect("dependencies/database/decisions.json",
                WIRE.writerWithDefaultPrettyPrinter().writeValueAsString(set) + "\n");
    }
}
