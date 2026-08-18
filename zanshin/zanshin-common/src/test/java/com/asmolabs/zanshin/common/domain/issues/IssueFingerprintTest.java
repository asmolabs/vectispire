package com.asmolabs.zanshin.common.domain.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * The golden vectors, run against the Java port.
 *
 * <p>These hashes were produced by the Python implementation and are already stored in every
 * live database. They are the only thing standing between a port and the silent loss of the
 * whole triage history, so they are read from the NestJS tree rather than copied: one file,
 * three implementations, no room for the two suites to stay green while disagreeing.
 *
 * <p>A failure here is never "update the expected value".
 */
@DisplayName("issue fingerprint")
class IssueFingerprintTest {

    @TestFactory
    @DisplayName("matches the vectors generated from the original implementation")
    List<DynamicTest> matchesGoldenVectors() throws Exception {
        JsonNode vectors;
        try (InputStream stream = getClass().getResourceAsStream("/issue-fingerprint.json")) {
            assertThat(stream)
                    .as("issue-fingerprint.json must be on the test classpath; an absent file "
                            + "would make this suite pass without checking anything")
                    .isNotNull();
            vectors = new ObjectMapper().readTree(stream);
        }

        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode vector : vectors) {
            JsonNode in = vector.get("input");
            String expected = vector.get("expected").asText();
            tests.add(DynamicTest.dynamicTest(vector.get("label").asText(), () -> assertThat(
                            IssueFingerprint.build(new IssueFingerprint.Input(
                                    integerOrNull(in, "repoId"),
                                    integerOrNull(in, "containerId"),
                                    textOrNull(in, "findingType"),
                                    textOrNull(in, "identifier"),
                                    textOrNull(in, "purl"),
                                    textOrNull(in, "packageName"),
                                    textOrNull(in, "filePath"))))
                    .isEqualTo(expected)));
        }

        assertThat(tests).as("the vector file must not be empty").isNotEmpty();
        return tests;
    }

    private static Integer integerOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asInt();
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }
}
