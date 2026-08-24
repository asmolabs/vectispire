package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.enrichment.Catalogs;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Enriching vulnerabilities from EPSS and the CISA KEV catalog.
 *
 * <p><b>These are the only network calls Vectispire makes during a scan, and they send nothing but
 * CVE identifiers</b> — never source code, never a SBOM. That is what separates them from a
 * cloud scanner, and what makes the trade acceptable.
 *
 * <p><b>Every failure is logged and swallowed.</b> A scan that produced real results must never
 * be marked failed because an optional API did not answer. The cost is real and visible on
 * screen: {@code isKev} stays false, so the "actively exploited" counter shows a reassuring
 * zero that means "we could not ask", not "there are none".
 */
@Service
public class EnrichmentService implements ScanIngestor.Enricher {

    private static final Logger log = LoggerFactory.getLogger(EnrichmentService.class);

    /** The KEV catalog changes at most once a day; re-reading it per scan would be waste. */
    private static final Duration KEV_CACHE_TTL = Duration.ofHours(24);

    private final SettingsService settings;
    private final OutboundJson outbound;
    private final Clock clock;

    private Set<String> kevCache = Set.of();
    private Instant kevFetchedAt = Instant.EPOCH;

    public EnrichmentService(SettingsService settings, OutboundJson outbound, Clock clock) {
        this.settings = settings;
        this.outbound = outbound;
        this.clock = clock;
    }

    /**
     * Sets the EPSS score and the exploited flag <b>in memory</b>.
     *
     * <p>Nothing is written here: the caller is in the middle of the ingestion transaction and
     * will save these findings itself. Writing from this service would impose its own
     * transaction and make findings appear in the database before the scan concluded — visible
     * half-way, with counters matching nothing.
     */
    @Override
    public void enrich(List<FindingEntity> findings) {
        if (!settings.isEnabled(Setting.ENRICHMENT_ENABLED)) {
            return;
        }

        List<FindingEntity> vulnerabilities = findings.stream()
                .filter(finding -> FindingType.VULNERABILITY.wireName().equals(finding.getType()))
                .filter(finding -> finding.getIdentifier() != null && !finding.getIdentifier().isBlank())
                .toList();
        if (vulnerabilities.isEmpty()) {
            return;
        }

        List<String> identifiers = List.copyOf(new TreeSet<>(vulnerabilities.stream()
                .map(FindingEntity::getIdentifier)
                .toList()));
        Map<String, Double> scores = epssScores(identifiers);
        Set<String> exploited = kevIdentifiers();

        int flagged = 0;
        for (FindingEntity finding : vulnerabilities) {
            // Only when known: overwriting with null would erase a score obtained on the
            // previous scan, on the day the API happens to be unavailable.
            Optional.ofNullable(scores.get(finding.getIdentifier())).ifPresent(finding::setEpssScore);
            finding.setIsKev(exploited.contains(finding.getIdentifier()));
            if (Boolean.TRUE.equals(finding.getIsKev())) {
                flagged++;
            }
        }

        log.info(
                "Enrichment: {}/{} CVE with an EPSS score, {} in the KEV catalog.",
                scores.size(),
                identifiers.size(),
                flagged);
    }

    private Map<String, Double> epssScores(List<String> identifiers) {
        Map<String, Double> scores = new HashMap<>();
        for (List<String> batch : Catalogs.batches(identifiers, Catalogs.EPSS_BATCH_SIZE)) {
            String url = Catalogs.EPSS_API_URL + "?cve="
                    + URLEncoder.encode(String.join(",", batch), StandardCharsets.UTF_8);
            try {
                outbound.get(url, OutboundPolicy.PUBLIC_ONLY, "EPSS")
                        .map(Catalogs::parseEpss)
                        .ifPresent(scores::putAll);
            } catch (RuntimeException unavailable) {
                // A lost batch does not cancel the others: partial enrichment beats none, and
                // the missing CVE are retried on the next scan.
                log.warn("EPSS lookup failed for a batch of {} CVE: {}", batch.size(), unavailable.getMessage());
            }
        }
        return scores;
    }

    private Set<String> kevIdentifiers() {
        if (!kevCache.isEmpty() && Duration.between(kevFetchedAt, clock.instant()).compareTo(KEV_CACHE_TTL) < 0) {
            return kevCache;
        }

        try {
            Optional<JsonNode> payload = outbound.get(Catalogs.KEV_CATALOG_URL, OutboundPolicy.PUBLIC_ONLY, "KEV catalog");
            Set<String> catalog = payload.map(Catalogs::parseKev).orElseGet(Set::of);
            // An empty catalog is never legitimate — it holds well over a thousand entries.
            // Caching it would mark every vulnerability as unexploited for twenty-four hours,
            // which is exactly the lie to avoid.
            if (catalog.isEmpty()) {
                log.warn("KEV catalog empty or unreadable: previous cache kept.");
            } else {
                kevCache = catalog;
                kevFetchedAt = clock.instant();
            }
        } catch (RuntimeException unavailable) {
            log.warn("KEV catalog fetch failed: {} — previous cache kept.", unavailable.getMessage());
        }

        return kevCache;
    }
}
