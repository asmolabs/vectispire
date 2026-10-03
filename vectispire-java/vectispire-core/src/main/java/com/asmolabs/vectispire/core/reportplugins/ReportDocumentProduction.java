package com.asmolabs.vectispire.core.reportplugins;

import com.fasterxml.jackson.annotation.JsonValue;
import java.time.Instant;

/**
 * One run that produced a document a holder asked about (decision 0035 §4, lot R7), as its provenance states it.
 *
 * @param producedAt when the run ended and the package was signed
 * @param signingKeyId the platform key that signed it, by its id — the SHA-256 of the public key
 * @param documentKept whether the installation still keeps the package, which the project's report route
 *     serves; false once the evidence window purged its bytes — the run and its digests stay, and so does its
 *     standing
 * @param withdrawnAt when the platform governor withdrew the manifest that produced it; null while it stands
 * @param withdrawnBy who withdrew it; null while it stands
 * @param withdrawalJustification why, as the governor wrote it; null while it stands
 */
public record ReportDocumentProduction(
        MatchedDigest matched,
        Long runId,
        Long projectId,
        String projectName,
        String pluginId,
        String manifestDigest,
        String imageDigest,
        String outputMediaType,
        String outputSha256,
        String packageSha256,
        Instant producedAt,
        String signingKeyId,
        boolean documentKept,
        Instant withdrawnAt,
        String withdrawnBy,
        String withdrawalJustification) {

    /** Which of a produced run's two digests the one asked about is. */
    public enum MatchedDigest {
        /** The zip a download hands out: the file, its signature and its provenance. */
        PACKAGE("package"),
        /** The plugin's file inside it — the provenance's subject, what a recipient holds once the zip is opened. */
        OUTPUT("output");

        private final String wireName;

        MatchedDigest(String wireName) {
            this.wireName = wireName;
        }

        @JsonValue
        public String wireName() {
            return wireName;
        }
    }
}
