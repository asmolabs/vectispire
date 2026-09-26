package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.scanners.DependencyScanner.DependencyFinding;
import com.asmolabs.vectispire.common.scanning.scanners.IacScanner.IacFinding;
import com.asmolabs.vectispire.common.scanning.scanners.SastScanner.SastFinding;
import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner.SecretFinding;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;

/**
 * Which finding types a scan declares it looked at.
 *
 * <p>Every assertion here is about that one question, because it is the question whose wrong
 * answer resolves a target's history without raising anything.
 */
@DisplayName("ingesting a scan's artifacts")
class ScanIngestorTest {

    private static final Instant NOW = Instant.parse("2026-08-13T10:00:00Z");

    /** The issue the backlog answers for every finding: whatever, so long as each gets one. */
    private static final long ISSUE = 41L;

    private ScanIngestor.Backlog sync;
    private com.asmolabs.vectispire.core.scanning.persistence.Findings rows;
    private ScanIngestor.InventorySink components;
    private ScanIngestor ingestor;

    @BeforeEach
    void wire() {
        sync = mock(ScanIngestor.Backlog.class);
        when(sync.reconcile(any())).thenAnswer(call -> reconciled(call.getArgument(0)));
        rows = mock(com.asmolabs.vectispire.core.scanning.persistence.Findings.class);
        components = mock(ScanIngestor.InventorySink.class);
        ingestor = ingestor(Optional.empty(), Optional.empty(), Optional.empty());
    }

    private ScanIngestor ingestor(
            Optional<ScanIngestor.Enricher> enricher,
            Optional<ScanIngestor.EndOfLifeSource> endOfLife,
            Optional<ScanIngestor.LicenseSource> licenses) {
        return new ScanIngestor(sync, rows, enricher, endOfLife, licenses, components, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static ScanIngestor.Reconciliation reconciled(ScanIngestor.Observation observation) {
        return new ScanIngestor.Reconciliation(0, 0, 0, 0, Collections.nCopies(observation.findings().size(), ISSUE));
    }

    private static ScanEntity scan() {
        ScanEntity scan = new ScanEntity();
        scan.setId(7L);
        scan.setRepoId(3L);
        return scan;
    }

    private ScanIngestor.Observation observation() {
        ArgumentCaptor<ScanIngestor.Observation> captor = ArgumentCaptor.forClass(ScanIngestor.Observation.class);
        org.mockito.Mockito.verify(sync).reconcile(captor.capture());
        return captor.getValue();
    }

    private Set<FindingType> scannedTypes() {
        return observation().scannedTypes();
    }

    /** The scan's rows, as written after the backlog answered. */
    @SuppressWarnings("unchecked")
    private List<FindingEntity> producedFindings() {
        ArgumentCaptor<List<FindingEntity>> captor = ArgumentCaptor.forClass(List.class);
        org.mockito.Mockito.verify(rows).saveAll(captor.capture());
        return captor.getValue();
    }

    @Nested
    @DisplayName("declaring what ran")
    class ScannedTypes {

        @Test
        @DisplayName("a step that did not run declares nothing")
        void absentStepsDeclareNothing() {
            // Everything absent: the scan looked at nothing, so nothing may be resolved.
            ingestor.ingest(scan(), ScanArtifacts.builder().build(Duration.ZERO));

            assertThat(scannedTypes()).isEmpty();
        }

        @Test
        @DisplayName("a step that ran and found nothing declares its type")
        void emptyResultsStillDeclare() {
            // This is the whole distinction: "the secrets scanner ran and found nothing" must
            // resolve the secret issues.
            ingestor.ingest(scan(), ScanArtifacts.builder().secrets(List.of()).build(Duration.ZERO));

            assertThat(scannedTypes()).containsExactly(FindingType.SECRET);
        }

        @Test
        @DisplayName("source analysis declares both of its types together")
        void sastDeclaresQualityToo() {
            // One pass looks for security and for quality. Declaring only one would silently
            // resolve the other's entire history.
            ingestor.ingest(scan(), ScanArtifacts.builder().sast(List.of()).build(Duration.ZERO));

            assertThat(scannedTypes()).containsExactlyInAnyOrder(FindingType.SAST, FindingType.QUALITY);
        }

        @Test
        @DisplayName("end of life is not declared without a source, even with an SBOM")
        void endOfLifeNeedsItsSource() {
            // "We stopped looking" is not "it is fixed": with detection off, nothing was
            // observed, and declaring the type would resolve its whole history.
            ingestor.ingest(scan(), ScanArtifacts.builder().sbom(sbom()).build(Duration.ZERO));

            assertThat(scannedTypes()).doesNotContain(FindingType.EOL);
        }

        @Test
        @DisplayName("end of life is not declared when its source is switched off")
        void disabledEndOfLifeDeclaresNothing() {
            ScanIngestor.EndOfLifeSource source = mock(ScanIngestor.EndOfLifeSource.class);
            when(source.isEnabled()).thenReturn(false);

            ingestor(Optional.empty(), Optional.of(source), Optional.empty())
                    .ingest(scan(), ScanArtifacts.builder().sbom(sbom()).build(Duration.ZERO));

            assertThat(scannedTypes()).doesNotContain(FindingType.EOL);
        }

        @Test
        @DisplayName("end of life is not declared when its lookup failed")
        void failedEndOfLifeDeclaresNothing() {
            // The defect: the type was declared before the call, and an outage returned an empty
            // list — "ran, found nothing" — which resolved every end-of-life issue of the target.
            ScanIngestor.EndOfLifeSource source = mock(ScanIngestor.EndOfLifeSource.class);
            when(source.isEnabled()).thenReturn(true);
            when(source.findings(any())).thenReturn(Optional.empty());

            ingestor(Optional.empty(), Optional.of(source), Optional.empty())
                    .ingest(scan(), ScanArtifacts.builder().sbom(sbom()).build(Duration.ZERO));

            assertThat(scannedTypes()).doesNotContain(FindingType.EOL);
        }

        @Test
        @DisplayName("end of life is declared when its lookup ran, even with nothing found")
        void emptyEndOfLifeIsDeclared() {
            ScanIngestor.EndOfLifeSource source = mock(ScanIngestor.EndOfLifeSource.class);
            when(source.isEnabled()).thenReturn(true);
            when(source.findings(any())).thenReturn(Optional.of(List.of()));

            ingestor(Optional.empty(), Optional.of(source), Optional.empty())
                    .ingest(scan(), ScanArtifacts.builder().sbom(sbom()).build(Duration.ZERO));

            assertThat(scannedTypes()).contains(FindingType.EOL);
        }

        @Test
        @DisplayName("licences are declared as soon as an SBOM exists")
        void licencesNeedNoRemoteService() {
            // Unlike end of life there is nothing remote to reach, so "no findings" genuinely
            // means "no forbidden licence" — including when the list is empty, in which case the
            // old findings should indeed resolve.
            ScanIngestor.LicenseSource source = mock(ScanIngestor.LicenseSource.class);
            when(source.findings(any())).thenReturn(List.of());

            ingestor(Optional.empty(), Optional.empty(), Optional.of(source))
                    .ingest(scan(), ScanArtifacts.builder().sbom(sbom()).build(Duration.ZERO));

            assertThat(scannedTypes()).contains(FindingType.LICENSE);
        }
    }

    @Nested
    @DisplayName("the findings produced")
    class Findings {

        @Test
        @DisplayName("a hardcoded secret is always serious")
        void secretsAreHigh() {
            // There is no severity to grade, only a key to revoke.
            ingestor.ingest(
                    scan(),
                    ScanArtifacts.builder()
                            .secrets(List.of(new SecretFinding("aws-key", "AWS token", "app.py", 12, "abc")))
                            .build(Duration.ZERO));

            assertThat(producedFindings()).singleElement().satisfies(finding -> {
                assertThat(finding.getSeverity()).isEqualTo(Severity.HIGH.wireName());
                assertThat(finding.getFilePath()).isEqualTo("app.py");
                assertThat(finding.getScanId()).isEqualTo(7L);
                // Set here because the column is mandatory and a database default would apply
                // after the insert — too late for the entity in memory.
                assertThat(finding.getCreatedAt()).isEqualTo(NOW);
                assertThat(finding.getIssueId()).as("each row points at the issue the backlog answered").isEqualTo(ISSUE);
            });
        }

        @Test
        @DisplayName("the rule's category decides which backlog it lands in")
        void categoryRoutesTheFinding() {
            ingestor.ingest(
                    scan(),
                    ScanArtifacts.builder()
                            .sast(List.of(
                                    new SastFinding("r1", "security", Severity.HIGH, null, "a.py", 1, "eval", "A03"),
                                    new SastFinding("r2", "maintainability", Severity.LOW, null, "b.py", 2, "long", null)))
                            .build(Duration.ZERO));

            assertThat(producedFindings())
                    .extracting(FindingEntity::getType)
                    .containsExactly(FindingType.SAST.wireName(), FindingType.QUALITY.wireName());

            // **The category the rule declares travels with the finding**, and an absent
            // declaration stays absent: giving it a default category would put a finding into a
            // category nobody claimed.
            assertThat(producedFindings())
                    .extracting(FindingEntity::getOwaspCategory)
                    .containsExactly("A03", null);
        }

        @Test
        @DisplayName("an IaC check keeps its documentation link")
        void iacKeepsItsGuideline() {
            ingestor.ingest(
                    scan(),
                    ScanArtifacts.builder()
                            .iac(List.of(new IacFinding("CKV_AWS_20", "S3 not public", "main.tf", 4,
                                    "https://docs/CKV_AWS_20", "aws_s3_bucket.x")))
                            .build(Duration.ZERO));

            assertThat(producedFindings()).singleElement().satisfies(finding -> {
                assertThat(finding.getLink()).isEqualTo("https://docs/CKV_AWS_20");
                assertThat(finding.getDescription()).isEqualTo("S3 not public");
            });
        }

        @Test
        @DisplayName("directness stays unknown rather than claiming transitive")
        void unknownDirectnessIsNull() {
            // A container scan cannot tell direct from transitive, and writing false would
            // claim it could — on the field an operator prioritizes by.
            ingestor.ingest(
                    scan(),
                    ScanArtifacts.builder()
                            .secrets(List.of(new SecretFinding("r", "d", "f", 1, null)))
                            .build(Duration.ZERO));

            assertThat(producedFindings().getFirst().getIsDirectDependency()).isNull();
        }
    }

    @Nested
    @DisplayName("low confidence")
    class Confidence {

        @ParameterizedTest(name = "{0} at low confidence becomes {1}")
        @CsvSource({"CRITICAL, HIGH", "HIGH, MEDIUM", "MEDIUM, LOW", "LOW, LOW"})
        void dropsOneRank(String from, String to) {
            // Dropped, not removed: removing makes the finding disappear and reappear as new the
            // day the metadata changes, triage lost. Below the default gate threshold is exactly
            // "visible in the backlog, unable to break a build".
            assertThat(ScanIngestor.downgradeLowConfidence(Severity.valueOf(from), "LOW"))
                    .isEqualTo(Severity.valueOf(to));
        }

        @Test
        @DisplayName("anything but low confidence is left alone")
        void othersAreUntouched() {
            assertThat(ScanIngestor.downgradeLowConfidence(Severity.CRITICAL, "HIGH")).isEqualTo(Severity.CRITICAL);
            assertThat(ScanIngestor.downgradeLowConfidence(Severity.CRITICAL, null)).isEqualTo(Severity.CRITICAL);
        }
    }

    @Test
    @DisplayName("enrichment runs before the write, not after, and what it found reaches the backlog")
    void enrichesBeforeSyncing() {
        // Enriching afterwards would need a second write outside the scan's transaction, and
        // would leave a window in which the gate sees findings without their exploited flag —
        // a green verdict on an actively exploited vulnerability.
        ScanIngestor.Enricher enricher = identifiers -> Optional.of(new ScanIngestor.Enrichment(
                Map.of("CVE-2024-1", 0.42), Set.of("CVE-2024-1")));

        ingestor(Optional.of(enricher), Optional.empty(), Optional.empty())
                .ingest(scan(), ScanArtifacts.builder().dependencies(List.of(vulnerability("CVE-2024-1"))).build(Duration.ZERO));

        assertThat(observation().findings()).singleElement().satisfies(finding -> {
            assertThat(finding.epssScore()).isEqualTo(0.42);
            assertThat(finding.kev()).isTrue();
        });
    }

    @Test
    @DisplayName("a CVE enrichment does not know keeps no score and is not exploited")
    void anUnknownCveIsLeftAlone() {
        // Only a known score is written: overwriting with null would erase one obtained on the
        // previous scan — through the issue it refreshes — on the day the API is unavailable.
        ScanIngestor.Enricher enricher = identifiers -> Optional.of(new ScanIngestor.Enrichment(Map.of(), Set.of()));

        ingestor(Optional.of(enricher), Optional.empty(), Optional.empty())
                .ingest(scan(), ScanArtifacts.builder().dependencies(List.of(vulnerability("CVE-2024-2"))).build(Duration.ZERO));

        assertThat(observation().findings()).singleElement().satisfies(finding -> {
            assertThat(finding.epssScore()).isNull();
            assertThat(finding.kev()).isFalse();
        });
    }

    @Test
    @DisplayName("findings of other types are not sent to the catalogs")
    void onlyVulnerabilitiesAreLookedUp() {
        ScanIngestor.Enricher enricher = mock(ScanIngestor.Enricher.class);

        ingestor(Optional.of(enricher), Optional.empty(), Optional.empty())
                .ingest(scan(), ScanArtifacts.builder()
                        .secrets(List.of(new SecretFinding("generic-api-key", "key", "app.py", 1, null)))
                        .build(Duration.ZERO));

        // Not "the flag stayed false" — nothing was asked at all. A secret's rule id has no
        // meaning to either catalog, and sending it would leak a rule name for no answer.
        org.mockito.Mockito.verifyNoInteractions(enricher);
    }

    @Test
    @DisplayName("the backlog folds the whole values; only the rows are clipped, after")
    void wholeValuesCrossAndRowsAreClipped() {
        // The path is a fingerprint input (AGENTS.md: a data contract). The backlog must see it
        // whole, or two findings sharing their first 500 characters would be one issue; the row
        // is clipped to its column, or one long path would fail the flush of the whole scan.
        String path = "src/" + "d/".repeat(400) + "Main.java";

        ingestor.ingest(scan(), ScanArtifacts.builder()
                .secrets(List.of(new SecretFinding("aws-key", "AWS token", path, 12, "abc")))
                .build(Duration.ZERO));

        assertThat(observation().findings()).singleElement()
                .satisfies(finding -> assertThat(finding.filePath()).isEqualTo(path));
        assertThat(producedFindings()).singleElement()
                .satisfies(finding -> assertThat(finding.getFilePath()).hasSize(500));
    }

    @Test
    @DisplayName("the scan's counts are the backlog's answer")
    void theCountsAreTheBacklogs() {
        org.mockito.Mockito.doAnswer(call -> {
            ScanIngestor.Observation observation = call.getArgument(0);
            return new ScanIngestor.Reconciliation(
                    2, 5, 0, 0, Collections.nCopies(observation.findings().size(), ISSUE));
        }).when(sync).reconcile(any());
        ScanEntity scan = scan();

        ingestor.ingest(scan, ScanArtifacts.builder().secrets(List.of()).build(Duration.ZERO));

        assertThat(scan.getNewIssuesCount()).isEqualTo(2);
        assertThat(scan.getResolvedIssuesCount()).isEqualTo(5);
    }

    @Test
    @DisplayName("hands API endpoints and contracts to the inventory")
    void recordsApiInventory() {
        ScanIngestor customIngestor = ingestor;

        var endpoint = new com.asmolabs.vectispire.common.domain.apis.ApiEndpoint(
                "POST", "/api/v1/checkout", true, "Bearer",
                com.asmolabs.vectispire.common.domain.apis.ApiVisibility.PUBLIC,
                "src/Controller.java", 20, "Spring Web", "checkout", "Process checkout", "checkout");

        ScanArtifacts artifacts = ScanArtifacts.builder()
                .apiEndpoints(List.of(endpoint))
                .apiContracts(List.of())
                .build(Duration.ZERO);

        ScanEntity s = scan();
        customIngestor.ingest(s, artifacts);

        // Explicitly empty travels as *present and empty*: the cataloguer ran and found no
        // contracts, so the inventory is right to clear them.
        org.mockito.Mockito.verify(components).apis(
                org.mockito.ArgumentMatchers.eq(s.getId()),
                org.mockito.ArgumentMatchers.eq(s.getRepoId()),
                org.mockito.ArgumentMatchers.eq(Optional.of(List.of(endpoint))),
                org.mockito.ArgumentMatchers.eq(Optional.of(List.<com.asmolabs.vectispire.common.domain.apis.ApiContract>of())));
    }

    @Test
    @DisplayName("a cataloguer that did not run stays absent, instead of arriving as an empty list")
    void anAbsentCataloguerIsNotAnEmptyInventory() {
        ScanIngestor customIngestor = ingestor;

        var endpoint = new com.asmolabs.vectispire.common.domain.apis.ApiEndpoint(
                "POST", "/api/v1/checkout", true, "Bearer",
                com.asmolabs.vectispire.common.domain.apis.ApiVisibility.PUBLIC,
                "src/Controller.java", 20, "Spring Web", "checkout", "Process checkout", "checkout");

        // The endpoint extractor ran; the contract cataloguer fell over. Before this was pinned,
        // the ingestor handed the inventory an empty contract list, the inventory deleted every
        // contract the repository had, and `ShadowApiDiff` then reported *every* endpoint as a
        // shadow API — a screen turned red by an analyzer failure rather than by an exposure.
        ScanArtifacts artifacts = ScanArtifacts.builder()
                .apiEndpoints(List.of(endpoint))
                .build(Duration.ZERO);

        ScanEntity s = scan();
        customIngestor.ingest(s, artifacts);

        org.mockito.Mockito.verify(components).apis(
                org.mockito.ArgumentMatchers.eq(s.getId()),
                org.mockito.ArgumentMatchers.eq(s.getRepoId()),
                org.mockito.ArgumentMatchers.eq(Optional.of(List.of(endpoint))),
                org.mockito.ArgumentMatchers.eq(Optional.<List<com.asmolabs.vectispire.common.domain.apis.ApiContract>>empty()));
    }

    private static DependencyFinding vulnerability(String cve) {
        return new DependencyFinding(cve, Severity.HIGH, "openssl", "1.1.1", "", null, null, "pkg:generic/openssl@1.1.1");
    }

    private static com.fasterxml.jackson.databind.JsonNode sbom() {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readTree("{\"artifacts\": []}");
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
