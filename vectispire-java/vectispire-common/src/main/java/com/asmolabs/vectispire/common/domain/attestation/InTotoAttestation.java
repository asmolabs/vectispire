package com.asmolabs.vectispire.common.domain.attestation;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Pure model for in-toto standard cryptographic attestations and SLSA supply chain provenance.
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

    public record PolicyAssessment(
            boolean gatePassed,
            List<String> violations,
            String enforcedPolicy) {}

    public record FindingsSummary(
            long critical,
            long high,
            long medium,
            long low,
            long kev,
            long secrets,
            long total) {}

    public static InTotoAttestation create(
            String targetName,
            String artifactSha256,
            Long scanId,
            String targetKind,
            String branch,
            String commitSha,
            Instant timestamp,
            boolean gatePassed,
            List<String> violations,
            String policyName,
            FindingsSummary findings,
            String sbomDigestSha256) {

        Subject subject = new Subject(
                targetName,
                artifactSha256 != null && !artifactSha256.isBlank()
                        ? Map.of("sha256", artifactSha256)
                        : Map.of("sha256", "0000000000000000000000000000000000000000000000000000000000000000"));

        Predicate predicate = new Predicate(
                new Builder("https://github.com/asmolabs/vectispire", "0.9.0"),
                new Invocation(scanId, targetKind, targetName, branch, commitSha, timestamp),
                new PolicyAssessment(gatePassed, violations != null ? violations : List.of(), policyName),
                findings,
                sbomDigestSha256);

        return new InTotoAttestation(IN_TOTO_STATEMENT_V01, List.of(subject), VECTISPIRE_PREDICATE_V1, predicate);
    }
}
