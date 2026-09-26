package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.services.shared.SettingsService;
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

@DisplayName("finding platforms whose support has ended")
class EndOfLifeServiceTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-08-18T12:00:00Z");

    private SettingsService settings;
    private OutboundJson outbound;
    private EndOfLifeService service;

    @BeforeEach
    void wire() {
        settings = mock(SettingsService.class);
        outbound = mock(OutboundJson.class);
        service = new EndOfLifeService(settings, outbound, Clock.fixed(NOW, ZoneOffset.UTC));

        when(settings.isEnabled(Setting.EOL_ENABLED)).thenReturn(true);
        when(settings.asInt(Setting.EOL_WARN_DAYS)).thenReturn(180);
        when(outbound.get(anyString(), any(), anyString())).thenReturn(Optional.empty());
        indexReturns("{\"result\":[]}");
    }

    @Test
    @DisplayName("the base image's distribution is found, which no package lookup would find")
    void reportsAnExpiredDistribution() {
        productReturns("debian", expired("10"));

        List<FindingEntity> findings = service.findings(scan(), sbom("""
                {"distro": {"id": "debian", "versionID": "10", "name": "Debian GNU/Linux"}, "artifacts": []}""")).orElseThrow();

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.getIdentifier()).isEqualTo("EOL-debian-10");
            assertThat(finding.getSeverity()).isEqualTo(Severity.HIGH.wireName());
            assertThat(finding.getPackageName()).isEqualTo("Debian GNU/Linux");
            assertThat(finding.getLink()).isEqualTo("https://endoflife.date/debian");
            // The recommended version reads like any other actionable finding's fix.
            assertThat(finding.getFixVersions()).isEqualTo("12.5");
            assertThat(finding.getFixState()).isEqualTo("fixed");
        });
    }

    @Test
    @DisplayName("the identifier names the cycle, not the patch")
    void theIdentifierIsStableAcrossPatches() {
        productReturns("python", expired("3.9"));
        indexReturns("""
                {"result": [{"identifier": "pkg:generic/python", "product": {"name": "python"}}]}""");

        List<FindingEntity> findings = service.findings(scan(), sbom("""
                {"artifacts": [{"name": "python", "version": "3.9.18", "purl": "pkg:generic/python@3.9.18"}]}""")).orElseThrow();

        // "python 3.9" reaches end of life, not "python 3.9.18". The fingerprint is built on
        // this, so the issue keeps its triage when the patch moves.
        assertThat(findings).singleElement().returns("EOL-python-3.9", FindingEntity::getIdentifier);
    }

    @Test
    @DisplayName("the same cycle seen twice produces one finding")
    void deduplicatesOnTheCycle() {
        productReturns("python", expired("3.9"));
        indexReturns("""
                {"result": [{"identifier": "pkg:generic/python", "product": {"name": "python"}}]}""");

        List<FindingEntity> findings = service.findings(scan(), sbom("""
                {"artifacts": [
                   {"name": "python", "version": "3.9.18", "purl": "pkg:generic/python@3.9.18"},
                   {"name": "python3", "version": "3.9.2", "purl": "pkg:generic/python@3.9.2"}]}""")).orElseThrow();

        assertThat(findings).hasSize(1);
    }

    @Test
    @DisplayName("a supported cycle produces nothing")
    void saysNothingAboutASupportedRelease() {
        productReturns("debian", """
                {"result": {"name": "debian", "releases": [
                   {"name": "12", "eolFrom": "2030-06-10", "isEol": false, "isMaintained": true,
                    "latest": {"name": "12.5"}}]}}""");

        // Present and empty: the step ran and found nothing, which may resolve the backlog.
        assertThat(service.findings(scan(), sbom("""
                {"distro": {"id": "debian", "versionID": "12", "name": "Debian"}, "artifacts": []}""")))
                .hasValueSatisfying(findings -> assertThat(findings).isEmpty());
    }

    @Test
    @DisplayName("a catalog outage makes the step absent, not empty")
    void anOutageIsAbsent() {
        // This test used to assert an empty list — the defect itself, written down as the
        // intended behaviour. Empty means "ran, found nothing", which resolves every end-of-life
        // issue of the target (decision 0007).
        when(outbound.get(anyString(), any(), anyString()))
                .thenThrow(new OutboundJson.OutboundFailureException("connection refused"));

        assertThat(service.findings(scan(), sbom("""
                {"distro": {"id": "debian", "versionID": "10"}, "artifacts": []}"""))).isEmpty();
    }

    @Test
    @DisplayName("one product unreachable makes the whole pass absent")
    void aPartialPassIsAbsent() {
        // A partial result would declare the type scanned while one product was never looked
        // at: that product's issue would resolve and its neighbours' would not.
        productReturns("debian", expired("10"));
        indexReturns("""
                {"result": [{"identifier": "pkg:generic/python", "product": {"name": "python"}}]}""");
        when(outbound.get(contains("/products/python/"), any(), anyString()))
                .thenThrow(new OutboundJson.OutboundFailureException("HTTP 503."));

        assertThat(service.findings(scan(), sbom("""
                {"distro": {"id": "debian", "versionID": "10", "name": "Debian"},
                 "artifacts": [{"name": "python", "version": "3.9.18", "purl": "pkg:generic/python@3.9.18"}]}""")))
                .isEmpty();
    }

    @Test
    @DisplayName("an outage is not cached: the next scan asks again")
    void anOutageIsNotCached() {
        // It was cached as an empty index for the whole TTL, which blinded the step for a day
        // after a single unreachable minute.
        when(outbound.get(contains("/identifiers/purl/"), any(), anyString()))
                .thenThrow(new OutboundJson.OutboundFailureException("connection refused"))
                .thenReturn(Optional.of(parse("{\"result\":[]}")));
        String document = """
                {"artifacts": []}""";

        assertThat(service.findings(scan(), sbom(document))).isEmpty();
        assertThat(service.findings(scan(), sbom(document))).isPresent();
    }

    @Test
    @DisplayName("an unknown product is asked for once, not once per package")
    void cachesTheAbsenceOfAProduct() {
        indexReturns("""
                {"result": [{"identifier": "pkg:generic/obscure", "product": {"name": "obscure"}}]}""");

        service.findings(scan(), sbom("""
                {"artifacts": [
                   {"name": "obscure", "version": "1.0", "purl": "pkg:generic/obscure@1.0"},
                   {"name": "obscure", "version": "1.1", "purl": "pkg:generic/obscure@1.1"}]}"""));

        verify(outbound, times(1)).get(contains("/products/obscure/"), any(), anyString());
    }

    @Test
    void describesTheFindingInWords() {
        FindingEntity finding = new FindingEntity();
        finding.setPackageName("debian");
        finding.setPackageVersion("10");

        assertThat(service.describe(finding)).contains("debian 10").contains("No fix will be published");
    }

    private void indexReturns(String body) {
        when(outbound.get(contains("/identifiers/purl/"), any(), anyString())).thenReturn(Optional.of(parse(body)));
    }

    private void productReturns(String name, String body) {
        when(outbound.get(contains("/products/" + name + "/"), any(), anyString())).thenReturn(Optional.of(parse(body)));
    }

    /** A product whose named cycle is over and whose recommended replacement is 12.5. */
    private static String expired(String cycle) {
        return """
                {"result": {"name": "p", "releases": [
                   {"name": "%s", "eolFrom": "2024-06-30", "isEol": true, "isMaintained": false},
                   {"name": "12", "eolFrom": "2030-06-10", "isEol": false, "isMaintained": true,
                    "latest": {"name": "12.5"}}]}}""".formatted(cycle);
    }

    private static JsonNode parse(String body) {
        try {
            return JSON.readTree(body);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static JsonNode sbom(String body) {
        return parse(body);
    }

    private static ScanEntity scan() {
        ScanEntity scan = new ScanEntity();
        scan.setId(3L);
        return scan;
    }
}
