package com.asmolabs.vectispire.common.domain.attestation;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * An in-toto statement about one completed scan: what it found, and what the gate said about it.
 *
 * <p><b>Every field is a claim a third party may act on</b>, so none is filled with a plausible
 * default. It used to be: a subject digest of sixty-four zeros, a builder version fixed at 0.9.0,
 * a gate "passed" computed as "no critical" under a policy named "Standard Policy" that existed
 * nowhere, KEV and secret counts hard-coded to zero. A consumer verifying the digest could match it
 * to nothing, and one reading the verdict read a rule no pipeline had applied.
 */
public record InTotoAttestation(
        String _type,
        List<Subject> subject,
        String predicateType,
        Predicate predicate) {

    public static final String IN_TOTO_STATEMENT_V01 = "https://in-toto.io/Statement/v0.1";
    public static final String VECTISPIRE_PREDICATE_V1 = "https://vectispire.dev/attestation/v1";

    public record Subject(
            String name,
            Map<String, String> digest) {}

    /**
     * @param policy {@code null} when no gate verdict was recorded for the target between this
     *     scan and the next: the gate was not asked, and "passed" would be an invention
     * @param builder whose {@code version} is {@code null} when the build carried no version
     */
    public record Predicate(
            Builder builder,
            Invocation invocation,
            PolicyAssessment policy,
            FindingsSummary findings,
            String sbomDigestSha256) {}

    public record Builder(String id, String version) {}

    public record Invocation(
            Long scanId,
            String targetKind,
            String targetName,
            String branch,
            String commitSha,
            Instant timestamp) {}

    /**
     * The gate verdict recorded for the target after this scan, as the gate recorded it.
     *
     * @param enforcedPolicy where the policy came from — the target's own, the global one, or the
     *     built-in default — as the verdict register names it
     * @param policyVersion the stored policy's version, {@code null} for the built-in default
     * @param decidedAt when the pipeline asked; the verdict judged the backlog as it stood then
     */
    public record PolicyAssessment(
            boolean gatePassed,
            List<String> violations,
            String enforcedPolicy,
            Long policyVersion,
            Instant decidedAt) {}

    public record FindingsSummary(
            long critical,
            long high,
            long medium,
            long low,
            long kev,
            long secrets,
            long total) {}

    /**
     * @param subjectName what the digest identifies
     * @param subjectSha256 required: a statement whose subject cannot be matched to anything is not
     *     an attestation, and refusing here is what keeps a caller from inventing one
     * @param policy {@code null} when the gate was not asked — see {@link Predicate}
     */
    public static InTotoAttestation create(
            String subjectName,
            String subjectSha256,
            String builderVersion,
            Long scanId,
            String targetKind,
            String targetName,
            String branch,
            String commitSha,
            Instant timestamp,
            PolicyAssessment policy,
            FindingsSummary findings,
            String sbomDigestSha256) {

        if (subjectSha256 == null || subjectSha256.isBlank()) {
            throw new IllegalArgumentException("An in-toto subject needs a digest; none was given.");
        }
        Subject subject = new Subject(subjectName, Map.of("sha256", subjectSha256));

        Predicate predicate = new Predicate(
                new Builder("https://github.com/asmolabs/vectispire", builderVersion),
                new Invocation(scanId, targetKind, targetName, branch, commitSha, timestamp),
                policy,
                findings,
                sbomDigestSha256);

        return new InTotoAttestation(IN_TOTO_STATEMENT_V01, List.of(subject), VECTISPIRE_PREDICATE_V1, predicate);
    }
}
