package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
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
        FindingEntity finding = vulnerability("CVE-2024-1");

        service.enrich(List.of(finding));

        assertThat(finding.getEpssScore()).isEqualTo(0.42);
        assertThat(finding.getIsKev()).isTrue();
    }

    @Test
    @DisplayName("a CVE the catalogs do not know keeps whatever it had")
    void anUnknownScoreIsNotOverwritten() {
        FindingEntity finding = vulnerability("CVE-2024-2");
        finding.setEpssScore(0.9);

        service.enrich(List.of(finding));

        // Overwriting with null would erase a score obtained on the previous scan, on the day
        // the API happens to be unavailable.
        assertThat(finding.getEpssScore()).isEqualTo(0.9);
        assertThat(finding.getIsKev()).isFalse();
    }

    @Test
    @DisplayName("an empty KEV catalog is refused rather than cached")
    void anEmptyCatalogKeepsThePreviousOne() {
        kevReturns("{\"vulnerabilities\":[{\"cveID\":\"CVE-2024-1\"}]}");
        service.enrich(List.of(vulnerability("CVE-2024-1")));

        // A KEV catalog holds well over a thousand entries. Caching an empty one would mark
        // every vulnerability as unexploited for twenty-four hours.
        kevReturns("{\"vulnerabilities\":[]}");
        FindingEntity finding = vulnerability("CVE-2024-1");
        service.enrich(List.of(finding));

        assertThat(finding.getIsKev()).isTrue();
    }

    @Test
    @DisplayName("a catalog outage costs its answer and nothing else")
    void anOutageDoesNotFailTheScan() {
        when(outbound.get(anyString(), any(), anyString()))
                .thenThrow(new OutboundJson.OutboundFailureException("connection refused"));
        FindingEntity finding = vulnerability("CVE-2024-1");

        service.enrich(List.of(finding));

        // The visible cost: false means "we could not ask", not "it is not exploited".
        assertThat(finding.getIsKev()).isFalse();
    }

    @Test
    void doesNothingWhenDisabled() {
        when(settings.isEnabled(Setting.ENRICHMENT_ENABLED)).thenReturn(false);
        FindingEntity finding = vulnerability("CVE-2024-1");

        service.enrich(List.of(finding));

        assertThat(finding.getEpssScore()).isNull();
    }

    @Test
    @DisplayName("findings of other types are not sent to the catalogs")
    void onlyVulnerabilitiesAreLookedUp() {
        FindingEntity secret = new FindingEntity();
        secret.setType(FindingType.SECRET.wireName());
        secret.setIdentifier("generic-api-key");

        service.enrich(List.of(secret));

        // Not "the flag stayed false" — nothing was asked at all. A secret's rule id has no
        // meaning to either catalog, and sending it would leak a rule name for no answer.
        verifyNoInteractions(outbound);
    }

    private void epssReturns(String body) {
        when(outbound.get(contains("epss"), eq(OutboundPolicy.PUBLIC_ONLY), anyString())).thenReturn(Optional.of(parse(body)));
    }

    private void kevReturns(String body) {
        when(outbound.get(contains("known_exploited"), eq(OutboundPolicy.PUBLIC_ONLY), anyString()))
                .thenReturn(Optional.of(parse(body)));
    }

    private static JsonNode parse(String body) {
        try {
            return JSON.readTree(body);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static FindingEntity vulnerability(String cve) {
        FindingEntity finding = new FindingEntity();
        finding.setType(FindingType.VULNERABILITY.wireName());
        finding.setIdentifier(cve);
        return finding;
    }
}
