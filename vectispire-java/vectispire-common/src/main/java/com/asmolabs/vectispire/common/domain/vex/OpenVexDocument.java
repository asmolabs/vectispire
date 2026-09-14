package com.asmolabs.vectispire.common.domain.vex;

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

    /**
     * The version this document claims, in one place.
     *
     * <p>It was written out at each construction site, and a claim repeated by hand is a claim
     * that can be repeated wrongly — which is what happened: the string said v0.2.0 while the
     * statements below it carried the v0.1.0 product shape.
     */
    public static final String CONTEXT = "https://openvex.dev/ns/v0.2.0";

    public static OpenVexDocument create(String documentUri, Instant timestamp, List<OpenVexStatement> statements) {
        return new OpenVexDocument(
                CONTEXT,
                documentUri,
                "Vectispire ASPM Control Plane",
                "Document Creator",
                timestamp != null ? timestamp : Instant.now(),
                1,
                // **Le nom que porte chaque document exporté.** Il annonçait un « Reachability &
                // Exploitability Engine » alors que la corrélation d'atteignabilité rapproche des
                // textes sans suivre de graphe d'appels — et ce champ `tooling` est précisément ce
                // qu'un lecteur regarde pour juger du poids d'une affirmation.
                "Vectispire ASPM",
                statements != null ? statements : List.of());
    }
}
