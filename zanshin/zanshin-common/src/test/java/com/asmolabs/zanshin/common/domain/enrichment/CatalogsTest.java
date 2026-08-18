package com.asmolabs.zanshin.common.domain.enrichment;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("enrichment catalogs")
class CatalogsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode json(String text) {
        try {
            return MAPPER.readTree(text);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    @Test
    @DisplayName("reads the score the API sends as a string")
    void readsStringScores() {
        // The central trap: the API returns "0.97512", not 0.97512.
        assertThat(Catalogs.parseEpss(json("""
                {"data": [{"cve": "CVE-2021-44228", "epss": "0.97512", "percentile": "0.99"}]}""")))
                .containsEntry("CVE-2021-44228", 0.97512);
    }

    @Test
    @DisplayName("an absent score stays absent rather than becoming zero")
    void absenceIsNotZero() {
        // Zero is a perfectly legitimate EPSS score, so a missing field converted numerically
        // reads as "zero probability of exploitation" — absence disguised as good news, on the
        // field an operator uses to decide what to leave alone.
        assertThat(Catalogs.parseEpss(json("""
                {"data": [{"cve": "CVE-1", "epss": null}, {"cve": "CVE-2", "epss": ""},
                          {"cve": "CVE-3"}, {"cve": "CVE-4", "epss": "not-a-number"}]}""")))
                .isEmpty();
    }

    @Test
    @DisplayName("a genuine zero is kept")
    void realZeroIsKept() {
        assertThat(Catalogs.parseEpss(json("{\"data\": [{\"cve\": \"CVE-1\", \"epss\": \"0\"}]}")))
                .containsEntry("CVE-1", 0.0);
    }

    @Test
    @DisplayName("an unreadable response yields nothing rather than throwing")
    void malformedResponsesAreEmpty() {
        assertThat(Catalogs.parseEpss(json("{}"))).isEmpty();
        assertThat(Catalogs.parseEpss(json("{\"data\": \"unexpected\"}"))).isEmpty();
        assertThat(Catalogs.parseEpss(null)).isEmpty();
    }

    @Test
    @DisplayName("reads the KEV identifiers, and nothing else")
    void readsKevIdentifiers() {
        assertThat(Catalogs.parseKev(json("""
                {"vulnerabilities": [{"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
                                     {"cveID": ""}, {"noId": true}]}""")))
                .containsExactly("CVE-2021-44228");
        assertThat(Catalogs.parseKev(json("{}"))).isEmpty();
    }

    @Test
    @DisplayName("splits a query into batches under the documented limit")
    void splitsIntoBatches() {
        // Too large a batch ends in a refusal which, here, would be swallowed — hence
        // enrichment silently absent rather than a visible error.
        List<Integer> items = IntStream.range(0, 200).boxed().toList();

        List<List<Integer>> batches = Catalogs.batches(items, Catalogs.EPSS_BATCH_SIZE);

        assertThat(batches).hasSize(3);
        assertThat(batches.get(0)).hasSize(90);
        assertThat(batches.get(2)).hasSize(20);
        assertThat(Catalogs.batches(List.of(), 90)).isEmpty();
    }
}
