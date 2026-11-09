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
    /**
     * The predicate this statement carries: every count of {@link FindingsSummary} in findings.
     *
     * <p><b>v1 is not served beside it.</b> v1's {@code findings.total} counted issues while its
     * severities counted findings (decision 0043 §6), and nothing in a v1 document says which unit
     * a reader is holding. Serving both would have needed a selector on the route and in the
     * evidence bundle, which 1.0 would then freeze with the defect it exists to retire. The type
     * changing is what makes the switch safe: a verifier that pins its predicate type — the reason
     * to have one — refuses a v2 statement rather than reading its {@code total} in the old unit.
     */
    public static final String VECTISPIRE_PREDICATE_V2 = "https://vectispire.dev/attestation/v2";

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

    /**
     * What the scan recorded, <b>counted in findings</b>: one per place a tool reported, so a rule
     * hitting a file twice counts two.
     *
     * <p>{@code critical} to {@code low} are the findings of that severity, {@code kev} those on an
     * actively exploited CVE, {@code secrets} those of type secret, and {@code total} every finding
     * of the scan, informational and unrated included. The categories overlap — a secret has a
     * severity too — so {@code total} is not their sum; it is never less than any of them.
     *
     * <p><b>In v1 {@code total} was the scan's issue count</b> — one per fingerprint, created,
     * reopened or still open — under the same name, and could be lower than the sum of the
     * severities. That is the defect v2 exists for; the field names are kept so that a verifier
     * moving from v1 changes the predicate type it pins and the meaning of one number, nothing else.
     */
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

        return new InTotoAttestation(IN_TOTO_STATEMENT_V01, List.of(subject), VECTISPIRE_PREDICATE_V2, predicate);
    }
}
