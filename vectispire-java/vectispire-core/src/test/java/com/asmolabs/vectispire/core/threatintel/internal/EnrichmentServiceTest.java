package com.asmolabs.vectispire.core.threatintel.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.scanning.ScanIngestor;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("enriching vulnerabilities from the public catalogs")
class EnrichmentServiceTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-08-18T12:00:00Z");

    private SettingsService settings;
    private OutboundJson outbound;
    private EnrichmentService service;

    @BeforeEach
    void wire() {
        settings = mock(SettingsService.class);
        outbound = mock(OutboundJson.class);
        service = new EnrichmentService(settings, outbound, Clock.fixed(NOW, ZoneOffset.UTC));

        when(settings.isEnabled(Setting.ENRICHMENT_ENABLED)).thenReturn(true);
        when(outbound.get(anyString(), any(), anyString())).thenReturn(Optional.empty());
    }

    @Test
    void setsTheScoreAndTheExploitedFlag() {
        epssReturns("{\"data\":[{\"cve\":\"CVE-2024-1\",\"epss\":\"0.42\"}]}");
        kevReturns("{\"vulnerabilities\":[{\"cveID\":\"CVE-2024-1\"}]}");

        ScanIngestor.Enrichment found = service.enrich(List.of("CVE-2024-1")).orElseThrow();

        assertThat(found.epssScores()).containsEntry("CVE-2024-1", 0.42);
        assertThat(found.exploited()).contains("CVE-2024-1");
    }

    @Test
    @DisplayName("a CVE the catalogs do not know gets no score, rather than a null one")
    void anUnknownScoreIsNotOverwritten() {
        ScanIngestor.Enrichment found = service.enrich(List.of("CVE-2024-2")).orElseThrow();

        // Absent from the map, not mapped to null: the ingestion writes only a known score, and
        // overwriting with null would erase one obtained on the previous scan, on the day the API
        // happens to be unavailable.
        assertThat(found.epssScores()).doesNotContainKey("CVE-2024-2");
        assertThat(found.exploited()).doesNotContain("CVE-2024-2");
    }

    @Test
    @DisplayName("an empty KEV catalog is refused rather than cached")
    void anEmptyCatalogKeepsThePreviousOne() {
        kevReturns("{\"vulnerabilities\":[{\"cveID\":\"CVE-2024-1\"}]}");
        service.enrich(List.of("CVE-2024-1"));

        // A KEV catalog holds well over a thousand entries. Caching an empty one would mark
        // every vulnerability as unexploited for twenty-four hours.
        kevReturns("{\"vulnerabilities\":[]}");

        assertThat(service.enrich(List.of("CVE-2024-1")).orElseThrow().exploited()).contains("CVE-2024-1");
    }

    @Test
    @DisplayName("a catalog outage costs its answer and nothing else")
    void anOutageDoesNotFailTheScan() {
        when(outbound.get(anyString(), any(), anyString()))
                .thenThrow(new OutboundJson.OutboundFailureException("connection refused"));
        when(outbound.get(anyString(), any(), anyString(), any(), org.mockito.ArgumentMatchers.anyLong()))
                .thenThrow(new OutboundJson.OutboundFailureException("connection refused"));

        ScanIngestor.Enrichment found = service.enrich(List.of("CVE-2024-1")).orElseThrow();

        // The visible cost: not exploited means "we could not ask", not "it is not exploited".
        assertThat(found.exploited()).doesNotContain("CVE-2024-1");
        assertThat(found.epssScores()).isEmpty();
    }

    @Test
    void doesNothingWhenDisabled() {
        when(settings.isEnabled(Setting.ENRICHMENT_ENABLED)).thenReturn(false);

        assertThat(service.enrich(List.of("CVE-2024-1"))).isEmpty();
        verifyNoInteractions(outbound);
    }

    @Test
    @DisplayName("nothing to look up asks nothing")
    void noIdentifierNoRequest() {
        // The ingestion sends vulnerabilities' identifiers only — a secret's rule id has no meaning
        // to either catalog, and sending it would leak a rule name for no answer — so a scan with
        // none sends an empty list, and that must not reach the network either.
        assertThat(service.enrich(List.of())).isEmpty();
        verifyNoInteractions(outbound);
    }

    private void epssReturns(String body) {
        when(outbound.get(contains("epss"), eq(OutboundPolicy.PUBLIC_ONLY), anyString())).thenReturn(Optional.of(parse(body)));
    }

    private void kevReturns(String body) {
        // With a ceiling of its own: the catalogue is larger than an ordinary answer.
        when(outbound.get(contains("known_exploited"), eq(OutboundPolicy.PUBLIC_ONLY), anyString(), any(),
                        org.mockito.ArgumentMatchers.longThat(ceiling -> ceiling > 4L * 1024 * 1024)))
                .thenReturn(Optional.of(parse(body)));
    }

    private static JsonNode parse(String body) {
        try {
            return JSON.readTree(body);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
