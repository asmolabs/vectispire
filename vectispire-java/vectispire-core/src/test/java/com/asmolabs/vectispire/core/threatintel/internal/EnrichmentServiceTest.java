package com.asmolabs.vectispire.core.threatintel.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.scanning.ScanIngestor;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.threatintel.persistence.KnownEpssScore;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("enriching vulnerabilities from the stored EPSS scores and KEV catalogue")
class EnrichmentServiceTest {

    private SettingsService settings;
    private ThreatIntelRepository intel;
    private ThreatIntelSyncRepository syncs;
    private EpssFeed epss;
    private EnrichmentService service;

    @BeforeEach
    void wire() {
        settings = mock(SettingsService.class);
        intel = mock(ThreatIntelRepository.class);
        syncs = mock(ThreatIntelSyncRepository.class);
        epss = mock(EpssFeed.class);
        service = new EnrichmentService(settings, intel, syncs, epss);

        when(settings.isEnabled(Setting.ENRICHMENT_ENABLED)).thenReturn(true);
        when(epss.synchronised()).thenReturn(true);
        when(epss.scoresOf(any())).thenReturn(Map.of());
        synced();
    }

    @Test
    void setsTheScoreAndTheExploitedFlag() {
        when(epss.scoresOf(Set.of("CVE-2024-1"))).thenReturn(Map.of("CVE-2024-1", new KnownEpssScore("CVE-2024-1", 0.42, 0.9)));
        when(intel.exploitedAmong(List.of("cve-2024-1"))).thenReturn(List.of("CVE-2024-1"));

        ScanIngestor.Enrichment found = service.enrich(List.of("CVE-2024-1")).orElseThrow();

        assertThat(found.epssScores()).containsEntry("CVE-2024-1", 0.42);
        assertThat(found.exploited()).containsExactly("CVE-2024-1");
    }

    @Test
    @DisplayName("a score and a flag are answered as the scan spelled the CVE, not as the feeds store it")
    void answeredInTheScansSpelling() {
        // The ingestion matches on its own spelling; both feeds are stored upper-case. Answered in the
        // feeds', a scanner reporting "cve-2021-44228" would never see its finding scored or flagged.
        when(intel.exploitedAmong(any())).thenReturn(List.of("CVE-2021-44228"));
        when(epss.scoresOf(Set.of("CVE-2021-44228")))
                .thenReturn(Map.of("CVE-2021-44228", new KnownEpssScore("CVE-2021-44228", 0.94, 0.99)));

        ScanIngestor.Enrichment found = service.enrich(List.of("cve-2021-44228")).orElseThrow();

        assertThat(found.exploited()).containsExactly("cve-2021-44228");
        assertThat(found.epssScores()).containsExactly(Map.entry("cve-2021-44228", 0.94));
    }

    @Test
    @DisplayName("before the first KEV synchronisation nothing is marked exploited, and the catalogue is not asked")
    void neverSyncedMarksNothing() {
        when(syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID)).thenReturn(Optional.of(new ThreatIntelSyncEntity()));

        ScanIngestor.Enrichment found = service.enrich(List.of("CVE-2024-1")).orElseThrow();

        assertThat(found.exploited()).isEmpty();
        verify(intel, never()).exploitedAmong(any());
    }

    @Test
    @DisplayName("before the first EPSS synchronisation no score is set — unknown, never a measured zero")
    void neverSyncedScoresNothing() {
        when(epss.synchronised()).thenReturn(false);

        ScanIngestor.Enrichment found = service.enrich(List.of("CVE-2024-1")).orElseThrow();

        assertThat(found.epssScores()).isEmpty();
        verify(epss, never()).scoresOf(any());
    }

    @Test
    @DisplayName("a CVE the feeds do not know gets no score, rather than a null one")
    void anUnknownScoreIsNotOverwritten() {
        ScanIngestor.Enrichment found = service.enrich(List.of("CVE-2024-2")).orElseThrow();

        // Absent from the map, not mapped to null: the ingestion writes only a known score, and
        // overwriting with null would erase one an earlier scan established.
        assertThat(found.epssScores()).doesNotContainKey("CVE-2024-2");
        assertThat(found.exploited()).doesNotContain("CVE-2024-2");
    }

    @Test
    void doesNothingWhenDisabled() {
        when(settings.isEnabled(Setting.ENRICHMENT_ENABLED)).thenReturn(false);

        assertThat(service.enrich(List.of("CVE-2024-1"))).isEmpty();
        verifyNoInteractions(epss, intel);
    }

    @Test
    @DisplayName("nothing to look up asks nothing")
    void noIdentifierNoRequest() {
        assertThat(service.enrich(List.of())).isEmpty();
        verifyNoInteractions(epss, intel);
    }

    private void synced() {
        ThreatIntelSyncEntity sync = new ThreatIntelSyncEntity();
        sync.setLastSyncedAt(Instant.parse("2026-09-27T06:00:00Z"));
        when(syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID)).thenReturn(Optional.of(sync));
    }
}
