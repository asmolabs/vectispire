package com.asmolabs.zanshin.common.domain.vex;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.List;

/**
 * An OpenVEX v0.2.0 document.
 * Spec: https://openvex.dev/ns/v0.2.0
 */
public record OpenVexDocument(
        @JsonProperty("@context") String context,
        @JsonProperty("@id") String id,
        @JsonProperty("author") String author,
        @JsonProperty("role") String role,
        @JsonProperty("timestamp") Instant timestamp,
        @JsonProperty("version") int version,
        @JsonProperty("tooling") String tooling,
        @JsonProperty("statements") List<OpenVexStatement> statements) {

    public static OpenVexDocument create(String documentUri, Instant timestamp, List<OpenVexStatement> statements) {
        return new OpenVexDocument(
                "https://openvex.dev/ns/v0.2.0",
                documentUri,
                "Zanshin ASPM Control Plane",
                "Document Creator",
                timestamp != null ? timestamp : Instant.now(),
                1,
                "Zanshin Reachability & Exploitability Engine",
                statements != null ? statements : List.of());
    }
}
