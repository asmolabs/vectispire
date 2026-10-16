package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
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
 * printed, not JSON) are pinned as {@code null} alongside the findings. The first three of each
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
            var findings = ContainerRunner.parseJson(printed(output), "grype (SBOM analysis)", List.of(0))
                    .map(DependencyScanner::findings);
            ReferenceSet.expect("dependencies/findings/" + output.getFileName(), WIRE.writeValueAsString(findings) + "\n");
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
}
