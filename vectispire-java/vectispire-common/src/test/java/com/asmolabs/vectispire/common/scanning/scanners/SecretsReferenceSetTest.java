package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.nio.file.Files;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Fixed gitleaks reports in, the findings the agent sends out — byte for byte as its JSON mapper
 * writes them — for the Rust port's secrets parser to match (see {@code ReferenceSet}).
 *
 * <p><b>The findings feed the issue fingerprint.</b> Rule id and path are part of it; a parser that
 * reads either differently resolves every secret issue and recreates it, its triage lost.
 *
 * <p>The mapper is built as {@code VectispireAgentApplication} builds it. Repeated here because that
 * class is the agent module's and this test is common's; the two lines that matter for these records —
 * no dates, nulls written — do not depend on the difference.
 */
class SecretsReferenceSetTest {

    private static final ObjectMapper WIRE = JsonMapper.builder()
            .addModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
            .addModule(new com.fasterxml.jackson.datatype.jdk8.Jdk8Module())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    @Test
    void theFindingsTheRustPortIsHeldTo() throws Exception {
        List<java.nio.file.Path> reports;
        try (Stream<java.nio.file.Path> listed = Files.list(ReferenceSet.resolve("secrets/reports"))) {
            reports = listed.filter(path -> path.toString().endsWith(".json")).sorted().toList();
        }
        for (var report : reports) {
            // As `SecretsScanner.scan` reads the file: the whole text, nothing stripped. An absent
            // reading is written `null` — `scan` then fails the step, it never sends "no secrets".
            Optional<List<SecretsScanner.SecretFinding>> findings = SecretsScanner.read(Files.readString(report));
            ReferenceSet.expect("secrets/findings/" + report.getFileName(), WIRE.writeValueAsString(findings) + "\n");
        }
    }
}
