package com.asmolabs.vectispire.core.threatintel.internal;

import com.asmolabs.vectispire.common.domain.enrichment.Catalogs;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.scanning.ScanIngestor;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Enriching vulnerabilities from EPSS and the CISA KEV catalogue.
 *
 * <p><b>The EPSS lookups are the only network calls Vectispire makes during a scan besides the
 * end-of-life catalogue, and they send nothing but CVE identifiers</b> — never source code, never a
 * SBOM. That is what separates them from a cloud scanner, and what makes the trade acceptable.
 *
 * <p><b>KEV is read from the catalogue the control plane stores</b>, not fetched per scan. This
 * service used to download the whole catalogue itself and cache it in memory for a day, per
 * instance, while the synchronisation screen fed a different table from a list typed into the code:
 * two answers to "is it exploited", and the one the SIEM heard about was the typed-in one. There is
 * one catalogue now, synchronised by {@code ThreatIntelFeedService}, and a scan asks it.
 *
 * <p><b>Every EPSS failure is logged and swallowed.</b> A scan that produced real results must never
 * be marked failed because an optional API did not answer. The cost is visible on screen: the score
 * stays unknown, which is what it is.
 */
@Service
public class EnrichmentService implements ScanIngestor.Enricher {

    private static final Logger log = LoggerFactory.getLogger(EnrichmentService.class);

    /** Kept well under every engine's bind-parameter ceiling, for a scan of a large image. */
    private static final int KEV_QUERY_BATCH = 500;

    private final SettingsService settings;
    private final OutboundJson outbound;
    private final ThreatIntelRepository intel;
    private final ThreatIntelSyncRepository syncs;

    public EnrichmentService(
            SettingsService settings, OutboundJson outbound, ThreatIntelRepository intel, ThreatIntelSyncRepository syncs) {
        this.settings = settings;
        this.outbound = outbound;
        this.intel = intel;
        this.syncs = syncs;
    }

    /**
     * The EPSS scores and the exploited identifiers among these — the vulnerabilities' of one scan,
     * sorted and distinct.
     *
     * <p><b>Called before the scan's transaction opens, never inside it</b> ({@code
     * ScanIngestor.prepare}): the EPSS lookups are network calls, ten seconds each at worst, and made
     * inside the ingestion they held the scan's row lock — the one fencing a concurrent reclaim — for
     * as long as the API took. {@code EnrichmentOutsideTransactionTest} runs a result through the
     * dispatcher and fails if a transaction is open here.
     *
     * <p><b>Nothing is written here</b>, and nothing is even set: the ingestion writes these values
     * onto its own findings, in its transaction, a score only where one is known — overwriting with
     * null would erase a score obtained on the previous scan, on the day the API happens to be
     * unavailable. Writing from this service would impose its own transaction and make findings
     * appear in the database before the scan concluded — visible half-way, with counters matching
     * nothing. It used to set them on the scan's rows in place; the rows are {@code scanning}'s
     * (decision 0029).
     */
    @Override
    public Optional<ScanIngestor.Enrichment> enrich(List<String> identifiers) {
        if (!settings.isEnabled(Setting.ENRICHMENT_ENABLED) || identifiers.isEmpty()) {
            return Optional.empty();
        }

        Map<String, Double> scores = epssScores(identifiers);
        Set<String> exploited = exploited(identifiers);

        log.info(
                "Enrichment: {}/{} CVE with an EPSS score, {} in the KEV catalogue.",
                scores.size(),
                identifiers.size(),
                exploited.size());
        return Optional.of(new ScanIngestor.Enrichment(scores, exploited));
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

    /**
     * The identifiers the stored catalogue lists, spelled as the scan spelled them — the ingestion
     * matches on its own spelling, and the catalogue is stored upper-case.
     *
     * <p>Before the first synchronisation there is no catalogue, and nothing can be marked exploited:
     * said in the log at warning level, because the zero it produces on screen means "not asked", and
     * the feed's status says so too. A refresh never un-flags an issue a scan does not find exploited
     * ({@code IssueSyncService}), so the gap costs new issues their flag until the first sync, which
     * re-evaluates them.
     */
    private Set<String> exploited(List<String> identifiers) {
        boolean synced = syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID)
                .map(ThreatIntelSyncEntity::getLastSyncedAt)
                .isPresent();
        if (!synced) {
            log.warn("KEV catalogue never synchronised: no finding of this scan can be marked as actively exploited.");
            return Set.of();
        }

        Map<String, List<String>> spellings = identifiers.stream()
                .collect(Collectors.groupingBy(id -> id.trim().toLowerCase(Locale.ROOT)));
        Set<String> exploited = new HashSet<>();
        for (List<String> batch : Catalogs.batches(List.copyOf(spellings.keySet()), KEV_QUERY_BATCH)) {
            intel.exploitedAmong(batch).forEach(stored ->
                    exploited.addAll(spellings.getOrDefault(stored.toLowerCase(Locale.ROOT), List.of())));
        }
        return exploited;
    }
}
