package com.asmolabs.vectispire.common.domain.reportplugins;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * What a report's package states of where its document came from (decision 0035 §3): an in-toto statement
 * (v1) whose subject is the output's SHA-256, signed by the platform's key inside a DSSE envelope — {@code
 * provenance.json} in the package, verified by {@code cosign verify-blob-attestation --type} {@value
 * #PREDICATE_TYPE}.
 *
 * <p><b>Provenance, not truth.</b> It claims that this installation gave this export, of this project, at this
 * instant, to this image, verified as built by this signer, at the request of this account, and that these are the
 * bytes the image wrote. It does not claim the document renders the export faithfully: a renderer can omit or
 * invent a line, and nothing short of parsing every format back into facts could tell. The export is kept and
 * its digest is here, so a doubter renders it again with the same pinned image. {@link Predicate#claim} says so
 * inside the signed statement, where a reader of the file finds it without the documentation.
 *
 * <p><b>Every field is one the run recorded</b> — the columns of {@code t_report_run} — and none is filled with a
 * plausible default: a signer known by key carries its key's SHA-256 and no identity, one known by identity no
 * key; an installation whose build states no version says null.
 */
public record ReportProvenance(
        @JsonProperty("_type") String type, List<Subject> subject, String predicateType, Predicate predicate) {

    public static final String STATEMENT_V1 = "https://in-toto.io/Statement/v1";
    public static final String PREDICATE_TYPE = "https://vectispire.dev/report-provenance/v1";

    /** The sentence the statement carries about itself — the guide's words. */
    public static final String CLAIM = "This installation gave this export, of this project, at this instant, to this "
            + "image, verified as built by this signer, at the request of this account, and these are the bytes the "
            + "image wrote. It does not claim the document is a true rendering of the export: the export is kept, "
            + "and rendering it again with the same image checks that.";

    public record Subject(String name, Map<String, String> digest) {}

    /**
     * @param claim {@link #CLAIM}: what the signature means, and what it does not
     */
    public record Predicate(
            Run run,
            Project project,
            Requester requester,
            Plugin plugin,
            Export export,
            Output output,
            Producer producer,
            String claim) {}

    /** The run, and the instants §3 names: requested, exported, started (claimed), finished. */
    public record Run(long id, Instant requestedAt, Instant startedAt, Instant exportedAt, Instant finishedAt) {}

    public record Project(long id, String name) {}

    /**
     * The account that asked, as the export names it — by display name, never an e-mail address; null where the
     * account has no display name.
     */
    public record Requester(long accountId, String displayName) {}

    /**
     * @param imageDigest the digest the image was pulled by, {@code sha256:<hex>}
     * @param signer who cosign verified had built it
     */
    public record Plugin(String id, String manifestDigest, String image, String imageDigest, Signer signer) {}

    /** Keyless: identity and issuer; by key: the SHA-256 of the key as the manifest holds it. */
    public record Signer(String identity, String issuer, String publicKeySha256) {}

    /** @param id the export's own identifier, {@code export.id} in it */
    public record Export(String schema, String schemaVersion, String id, String sha256, long size) {}

    public record Output(String name, String mediaType, String sha256, long size) {}

    /**
     * @param productVersion the Vectispire version that ran it; null when the build states none
     * @param signingKeyId the SHA-256 of the platform's public key, as every Vectispire signature names it
     */
    public record Producer(String productVersion, String signingKeyId) {}

    /** The statement, its subject the output. */
    public static ReportProvenance of(Predicate predicate) {
        Objects.requireNonNull(predicate.output(), "output");
        Objects.requireNonNull(predicate.output().sha256(), "the output's digest");
        return new ReportProvenance(STATEMENT_V1,
                List.of(new Subject(predicate.output().name(), Map.of("sha256", predicate.output().sha256()))),
                PREDICATE_TYPE, predicate);
    }
}
