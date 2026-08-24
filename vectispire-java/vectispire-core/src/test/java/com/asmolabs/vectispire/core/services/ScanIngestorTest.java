package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.scanners.IacScanner.IacFinding;
import com.asmolabs.vectispire.common.scanning.scanners.SastScanner.SastFinding;
import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner.SecretFinding;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
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

    private IssueSyncService sync;
    private ComponentInventory components;
    private ScanIngestor ingestor;

    @BeforeEach
    void wire() {
        sync = mock(IssueSyncService.class);
        when(sync.sync(any(), any(), any(), any(), any()))
                .thenReturn(new IssueSyncService.SyncResult(0, 0, 0, 0, List.of(), List.of()));
        components = mock(ComponentInventory.class);
        ingestor = new ScanIngestor(
                sync, Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                components,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static ScanEntity scan() {
        ScanEntity scan = new ScanEntity();
        scan.setId(7L);
        scan.setRepoId(3L);
        return scan;
    }

    @SuppressWarnings("unchecked")
    private Set<FindingType> scannedTypes() {
        ArgumentCaptor<Set<FindingType>> captor = ArgumentCaptor.forClass(Set.class);
        org.mockito.Mockito.verify(sync).sync(any(), any(), captor.capture(), any(), any());
        return captor.getValue();
    }

    @SuppressWarnings("unchecked")
    private List<FindingEntity> producedFindings() {
        ArgumentCaptor<List<FindingEntity>> captor = ArgumentCaptor.forClass(List.class);
        org.mockito.Mockito.verify(sync).sync(any(), captor.capture(), any(), any(), any());
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

            new ScanIngestor(sync, Optional.empty(), Optional.of(source), Optional.empty(), Optional.empty(), components,
                            Clock.fixed(NOW, ZoneOffset.UTC))
                    .ingest(scan(), ScanArtifacts.builder().sbom(sbom()).build(Duration.ZERO));

            assertThat(scannedTypes()).doesNotContain(FindingType.EOL);
        }

        @Test
        @DisplayName("licences are declared as soon as an SBOM exists")
        void licencesNeedNoRemoteService() {
            // Unlike end of life there is nothing remote to reach, so "no findings" genuinely
            // means "no forbidden licence" — including when the list is empty, in which case the
            // old findings should indeed resolve.
            ScanIngestor.LicenseSource source = mock(ScanIngestor.LicenseSource.class);
            when(source.findings(any(), any())).thenReturn(List.of());

            new ScanIngestor(sync, Optional.empty(), Optional.empty(), Optional.of(source), Optional.empty(), components,
                            Clock.fixed(NOW, ZoneOffset.UTC))
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
                // after the insert — too late for the entity the reconciliation reads.
                assertThat(finding.getCreatedAt()).isEqualTo(NOW);
            });
        }

        @Test
        @DisplayName("the rule's category decides which backlog it lands in")
        void categoryRoutesTheFinding() {
            ingestor.ingest(
                    scan(),
                    ScanArtifacts.builder()
                            .sast(List.of(
                                    new SastFinding("r1", "security", Severity.HIGH, null, "a.py", 1, "eval"),
                                    new SastFinding("r2", "maintainability", Severity.LOW, null, "b.py", 2, "long")))
                            .build(Duration.ZERO));

            assertThat(producedFindings())
                    .extracting(FindingEntity::getType)
                    .containsExactly(FindingType.SAST.wireName(), FindingType.QUALITY.wireName());
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
    @DisplayName("enrichment runs before the write, not after")
    void enrichesBeforeSyncing() {
        // Enriching afterwards would need a second write outside the scan's transaction, and
        // would leave a window in which the gate sees findings without their exploited flag —
        // a green verdict on an actively exploited vulnerability.
        AtomicReference<Boolean> enrichedBeforeSync = new AtomicReference<>(false);
        ScanIngestor.Enricher enricher = findings -> enrichedBeforeSync.set(true);
        when(sync.sync(any(), any(), any(), any(), any())).thenAnswer(call -> {
            assertThat(enrichedBeforeSync.get()).as("enrichment must have run already").isTrue();
            return new IssueSyncService.SyncResult(0, 0, 0, 0, List.of(), List.of());
        });

        new ScanIngestor(sync, Optional.of(enricher), Optional.empty(), Optional.empty(), Optional.empty(), components,
                        Clock.fixed(NOW, ZoneOffset.UTC))
                .ingest(scan(), ScanArtifacts.builder().secrets(List.of()).build(Duration.ZERO));

        assertThat(enrichedBeforeSync.get()).isTrue();
    }

    @Test
    @DisplayName("the notification is queued through the pre-commit hook, not after the sync")
    void notifiesInsideTheTransaction() {
        // A notification written one line later is lost by the very crash the outbox covers.
        AtomicReference<Boolean> notified = new AtomicReference<>(false);
        ScanIngestor.NotificationSink sink = (scan, result) -> notified.set(true);

        when(sync.sync(any(), any(), any(), any(), any())).thenAnswer(call -> {
            java.util.function.Consumer<IssueSyncService.SyncResult> hook = call.getArgument(4);
            IssueSyncService.SyncResult result = new IssueSyncService.SyncResult(1, 0, 0, 0, List.of(), List.of());
            hook.accept(result);
            return result;
        });

        new ScanIngestor(sync, Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(sink), components,
                        Clock.fixed(NOW, ZoneOffset.UTC))
                .ingest(scan(), ScanArtifacts.builder().secrets(List.of()).build(Duration.ZERO));

        assertThat(notified.get()).isTrue();
    }

    @Test
    @DisplayName("records API endpoints and contracts into ApiInventoryService")
    void recordsApiInventory() {
        ApiInventoryService apiService = mock(ApiInventoryService.class);
        ScanIngestor customIngestor = new ScanIngestor(
                sync, Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                components, Optional.of(apiService),
                Clock.fixed(NOW, ZoneOffset.UTC));

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

        org.mockito.Mockito.verify(apiService).record(
                org.mockito.ArgumentMatchers.eq(s),
                org.mockito.ArgumentMatchers.eq(List.of(endpoint)),
                org.mockito.ArgumentMatchers.eq(List.of()));
    }

    private static com.fasterxml.jackson.databind.JsonNode sbom() {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readTree("{\"artifacts\": []}");
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
