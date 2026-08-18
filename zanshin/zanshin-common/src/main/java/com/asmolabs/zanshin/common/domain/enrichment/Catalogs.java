package com.asmolabs.zanshin.common.domain.enrichment;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reading the two public catalogs Zanshin enriches findings from.
 *
 * <p>Metadata only leaves the machine: CVE identifiers, never code and never a SBOM.
 */
public final class Catalogs {

    private Catalogs() {}

    /** The EPSS API. Nothing but CVE identifiers is sent there. */
    public static final String EPSS_API_URL = "https://api.first.org/data/v1/epss";

    /** The catalog of actively exploited vulnerabilities, published by CISA. */
    public static final String KEV_CATALOG_URL =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    /**
     * The size of an EPSS query batch.
     *
     * <p>Under the limit the API documents: too large a batch ends in a refusal which, here,
     * would be swallowed — hence enrichment silently absent rather than a visible error.
     */
    public static final int EPSS_BATCH_SIZE = 90;

    /**
     * A response's EPSS scores, indexed by CVE.
     *
     * <p><b>The API returns the score as a string</b>, {@code "0.00042"}, not as a number. The
     * type check comes before the conversion, and that is not decorative caution: an absent or
     * empty field converts to <b>zero</b>, which is a perfectly legitimate EPSS score. Without
     * the guard, absence reads as "zero probability of exploitation" — absence disguised as
     * good news, on the field an operator uses to decide what to leave alone.
     */
    public static Map<String, Double> parseEpss(JsonNode payload) {
        Map<String, Double> scores = new HashMap<>();
        JsonNode data = payload == null ? null : payload.path("data");
        if (data == null || !data.isArray()) {
            return scores;
        }

        for (JsonNode entry : data) {
            JsonNode cve = entry.path("cve");
            if (!cve.isTextual() || cve.asText().isEmpty()) {
                continue;
            }
            JsonNode epss = entry.path("epss");
            if (!epss.isNumber() && !(epss.isTextual() && !epss.asText().isBlank())) {
                continue;
            }
            try {
                double value = epss.isNumber() ? epss.asDouble() : Double.parseDouble(epss.asText().trim());
                if (Double.isFinite(value)) {
                    scores.put(cve.asText(), value);
                }
            } catch (NumberFormatException notANumber) {
                // A score that cannot be read is left absent rather than defaulted. Zero would
                // be a claim; absence is the truth.
            }
        }
        return scores;
    }

    /** The KEV catalog's identifiers. */
    public static Set<String> parseKev(JsonNode payload) {
        Set<String> identifiers = new HashSet<>();
        JsonNode vulnerabilities = payload == null ? null : payload.path("vulnerabilities");
        if (vulnerabilities == null || !vulnerabilities.isArray()) {
            return identifiers;
        }

        for (JsonNode entry : vulnerabilities) {
            JsonNode id = entry.path("cveID");
            if (id.isTextual() && !id.asText().isEmpty()) {
                identifiers.add(id.asText());
            }
        }
        return identifiers;
    }

    /** Splits a list of CVEs into queryable batches. */
    public static <T> List<List<T>> batches(List<T> items, int size) {
        List<List<T>> batches = new ArrayList<>();
        for (int index = 0; index < items.size(); index += size) {
            batches.add(List.copyOf(items.subList(index, Math.min(index + size, items.size()))));
        }
        return batches;
    }
}
