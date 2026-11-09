package com.asmolabs.vectispire.common.domain.threatintel;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("reading CISA's KEV catalogue")
class KevCatalogTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    @DisplayName("reads the entries, the day each was added, the version and the release date")
    void readsTheCatalogue() {
        KevCatalog catalog = KevCatalog.parse(json("""
                {"title": "CISA Catalog of Known Exploited Vulnerabilities",
                 "catalogVersion": "2026.09.26", "dateReleased": "2026-09-26T15:01:12.0339Z", "count": 2,
                 "vulnerabilities": [
                   {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "dateAdded": "2021-12-10"},
                   {"cveID": "cve-2023-34362", "dateAdded": "not a date"}]}"""));

        assertThat(catalog.version()).isEqualTo("2026.09.26");
        assertThat(catalog.released()).isEqualTo(Instant.parse("2026-09-26T15:01:12.0339Z"));
        // Upper-cased: the feed and the scanners disagree on case, and the table is keyed on it.
        assertThat(catalog.added()).containsOnlyKeys("CVE-2021-44228", "CVE-2023-34362");
        assertThat(catalog.added().get("CVE-2021-44228")).isEqualTo(Instant.parse("2021-12-10T00:00:00Z"));
        // Unknown, not invented: an entry whose day cannot be read is still an entry.
        assertThat(catalog.added().get("CVE-2023-34362")).isNull();
    }

    @Test
    @DisplayName("what is not a CVE identifier is not an entry")
    void onlyCveIdentifiers() {
        KevCatalog catalog = KevCatalog.parse(json("""
                {"vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": ""}, {"noId": true},
                                     {"cveID": "'; drop table t_threat_intel_feed; --"}]}"""));

        assertThat(catalog.added()).containsOnlyKeys("CVE-2021-44228");
        assertThat(catalog.version()).isNull();
        assertThat(catalog.released()).isNull();
    }

    @Test
    @DisplayName("a document that is not the catalogue is refused, never read as an empty one")
    void notTheCatalogue() {
        // An empty catalogue applied as such would un-flag every exploited vulnerability in the
        // backlog — the gate green on Log4Shell because a mirror answered with an error page in JSON.
        assertThatThrownBy(() -> KevCatalog.parse(json("{}"))).isInstanceOf(KevCatalog.Unreadable.class);
        assertThatThrownBy(() -> KevCatalog.parse(json("{\"vulnerabilities\": \"none\"}")))
                .isInstanceOf(KevCatalog.Unreadable.class);
        assertThatThrownBy(() -> KevCatalog.parse(json("{\"vulnerabilities\": []}")))
                .isInstanceOf(KevCatalog.Unreadable.class)
                .hasMessageContaining("no vulnerability");
        assertThatThrownBy(() -> KevCatalog.parse(null)).isInstanceOf(KevCatalog.Unreadable.class);
    }

    @Test
    @DisplayName("a catalogue carrying fewer entries than it declares is refused as incomplete")
    void aTruncatedCatalogueIsRefused() {
        // The failure a truncating mirror produces: valid JSON, most of the list, and every CVE it
        // lost read as "no longer exploited".
        assertThatThrownBy(() -> KevCatalog.parse(json("""
                {"count": 3, "vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2023-34362"}]}""")))
                .isInstanceOf(KevCatalog.Unreadable.class)
                .hasMessageContaining("incomplete");
    }

    @Test
    @DisplayName("a version longer than its column is clipped, not refused")
    void aLongVersionIsClipped() {
        KevCatalog catalog = KevCatalog.parse(json("{\"catalogVersion\": \"" + "9".repeat(80)
                + "\", \"vulnerabilities\": [{\"cveID\": \"CVE-2021-44228\"}]}"));

        assertThat(catalog.version()).hasSize(KevCatalog.VERSION_MAX);
    }

    private static JsonNode json(String text) {
        try {
            return JSON.readTree(text);
        } catch (Exception unreadable) {
            throw new AssertionError(unreadable);
        }
    }
}
