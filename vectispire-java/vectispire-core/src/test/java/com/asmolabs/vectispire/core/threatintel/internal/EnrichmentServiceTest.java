package com.asmolabs.vectispire.core.threatintel.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.scanning.ScanIngestor;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("enriching vulnerabilities from EPSS and the stored KEV catalogue")
class EnrichmentServiceTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private SettingsService settings;
    private OutboundJson outbound;
    private ThreatIntelRepository intel;
    private ThreatIntelSyncRepository syncs;
    private EnrichmentService service;

    @BeforeEach
    void wire() {
        settings = mock(SettingsService.class);
        outbound = mock(OutboundJson.class);
        intel = mock(ThreatIntelRepository.class);
        syncs = mock(ThreatIntelSyncRepository.class);
        service = new EnrichmentService(settings, outbound, intel, syncs);

        when(settings.isEnabled(Setting.ENRICHMENT_ENABLED)).thenReturn(true);
        when(outbound.get(anyString(), any(), anyString())).thenReturn(Optional.empty());
        synced();
    }

    @Test
    void setsTheScoreAndTheExploitedFlag() {
        epssReturns("{\"data\":[{\"cve\":\"CVE-2024-1\",\"epss\":\"0.42\"}]}");
        when(intel.exploitedAmong(List.of("cve-2024-1"))).thenReturn(List.of("CVE-2024-1"));

        ScanIngestor.Enrichment found = service.enrich(List.of("CVE-2024-1")).orElseThrow();

        assertThat(found.epssScores()).containsEntry("CVE-2024-1", 0.42);
        assertThat(found.exploited()).containsExactly("CVE-2024-1");
    }

    @Test
    @DisplayName("an exploited CVE is answered as the scan spelled it, not as the catalogue stores it")
    void answeredInTheScansSpelling() {
        // The ingestion matches on its own spelling; the catalogue is stored upper-case. Answered in
        // the catalogue's, a scanner reporting "cve-2021-44228" would never see its finding flagged.
        when(intel.exploitedAmong(any())).thenReturn(List.of("CVE-2021-44228"));

        ScanIngestor.Enrichment found = service.enrich(List.of("cve-2021-44228")).orElseThrow();

        assertThat(found.exploited()).containsExactly("cve-2021-44228");
    }

    @Test
    @DisplayName("KEV is read from the stored catalogue: the scan downloads nothing from CISA")
    void kevIsNotFetchedPerScan() {
        service.enrich(List.of("CVE-2024-1"));

        // It used to fetch the catalogue itself and hold it for a day, per instance — a second
        // answer to "is it exploited" beside the one the SIEM heard about.
        verify(outbound, never()).get(contains("known_exploited"), any(), anyString(), any(), anyLong());
        verify(intel).exploitedAmong(List.of("cve-2024-1"));
    }

    @Test
    @DisplayName("before the first synchronisation nothing is marked exploited, and the catalogue is not asked")
    void neverSyncedMarksNothing() {
        when(syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID)).thenReturn(Optional.of(new ThreatIntelSyncEntity()));

        ScanIngestor.Enrichment found = service.enrich(List.of("CVE-2024-1")).orElseThrow();

        assertThat(found.exploited()).isEmpty();
        verify(intel, never()).exploitedAmong(any());
    }

    @Test
    @DisplayName("a CVE the catalogues do not know gets no score, rather than a null one")
    void anUnknownScoreIsNotOverwritten() {
        ScanIngestor.Enrichment found = service.enrich(List.of("CVE-2024-2")).orElseThrow();

        // Absent from the map, not mapped to null: the ingestion writes only a known score, and
        // overwriting with null would erase one obtained on the previous scan, on the day the API
        // happens to be unavailable.
        assertThat(found.epssScores()).doesNotContainKey("CVE-2024-2");
        assertThat(found.exploited()).doesNotContain("CVE-2024-2");
    }

    @Test
    @DisplayName("an EPSS outage costs its answer and nothing else")
    void anOutageDoesNotFailTheScan() {
        when(outbound.get(anyString(), any(), anyString()))
                .thenThrow(new OutboundJson.OutboundFailureException("connection refused"));
        when(intel.exploitedAmong(any())).thenReturn(List.of("CVE-2024-1"));

        ScanIngestor.Enrichment found = service.enrich(List.of("CVE-2024-1")).orElseThrow();

        assertThat(found.epssScores()).isEmpty();
        assertThat(found.exploited()).containsExactly("CVE-2024-1");
    }

    @Test
    void doesNothingWhenDisabled() {
        when(settings.isEnabled(Setting.ENRICHMENT_ENABLED)).thenReturn(false);

        assertThat(service.enrich(List.of("CVE-2024-1"))).isEmpty();
        verifyNoInteractions(outbound, intel);
    }

    @Test
    @DisplayName("nothing to look up asks nothing")
    void noIdentifierNoRequest() {
        // The ingestion sends vulnerabilities' identifiers only — a secret's rule id has no meaning
        // to either catalog, and sending it would leak a rule name for no answer — so a scan with
        // none sends an empty list, and that must not reach the network either.
        assertThat(service.enrich(List.of())).isEmpty();
        verifyNoInteractions(outbound, intel);
    }

    private void synced() {
        ThreatIntelSyncEntity sync = new ThreatIntelSyncEntity();
        sync.setLastSyncedAt(Instant.parse("2026-09-27T06:00:00Z"));
        when(syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID)).thenReturn(Optional.of(sync));
    }

    private void epssReturns(String body) {
        when(outbound.get(contains("epss"), eq(OutboundPolicy.PUBLIC_ONLY), anyString())).thenReturn(Optional.of(parse(body)));
    }

    private static JsonNode parse(String body) {
        try {
            return JSON.readTree(body);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
