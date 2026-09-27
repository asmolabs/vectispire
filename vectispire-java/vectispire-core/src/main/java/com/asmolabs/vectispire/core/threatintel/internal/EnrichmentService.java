package com.asmolabs.vectispire.core.threatintel.internal;

import com.asmolabs.vectispire.common.domain.enrichment.Catalogs;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.scanning.ScanIngestor;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.threatintel.persistence.KnownEpssScore;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
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
 * Enriching vulnerabilities from the stored EPSS scores and the stored CISA KEV catalogue.
 *
 * <p><b>A scan asks nobody.</b> The EPSS scores were asked of {@code api.first.org} here, ninety CVE
 * at a time, for every scan: a third party learned which vulnerabilities each repository carried the
 * day it was scanned — the estate's exploitable inventory, which this product exists to keep inside
 * the organisation — and on an estate without outbound access every score stayed unknown. Both
 * feeds are synchronised by the control plane now, whole, and a scan reads what was stored ({@code
 * EpssFeed}, {@code ThreatIntelFeedService}). {@code NoOutboundDuringIngestionTest} runs a scan
 * result through the real ingestion with a sender that fails the test if anything is sent.
 *
 * <p><b>KEV was the same story, earlier.</b> This service downloaded the whole catalogue itself and
 * cached it for a day, per instance, while the synchronisation screen fed a different table: two
 * answers to "is it exploited". There is one catalogue, and a scan asks it.
 *
 * <p><b>Before a feed's first synchronisation it knows nothing</b>, and says so at warning level: no
 * score is set and nothing is marked exploited, which the ingestion leaves as unknown — never as a
 * measured zero.
 */
@Service
public class EnrichmentService implements ScanIngestor.Enricher {

    private static final Logger log = LoggerFactory.getLogger(EnrichmentService.class);

    /** Kept well under every engine's bind-parameter ceiling, for a scan of a large image. */
    private static final int KEV_QUERY_BATCH = 500;

    private final SettingsService settings;
    private final ThreatIntelRepository intel;
    private final ThreatIntelSyncRepository syncs;
    private final EpssFeed epss;

    public EnrichmentService(
            SettingsService settings, ThreatIntelRepository intel, ThreatIntelSyncRepository syncs, EpssFeed epss) {
        this.settings = settings;
        this.intel = intel;
        this.syncs = syncs;
        this.epss = epss;
    }

    /**
     * The EPSS scores and the exploited identifiers among these — the vulnerabilities' of one scan,
     * sorted and distinct.
     *
     * <p><b>Called before the scan's transaction opens</b> ({@code ScanIngestor.prepare}). The lookups
     * are local reads now, and would be harmless inside it; the ordering stays because it costs
     * nothing and {@code EnrichmentOutsideTransactionTest} pins it.
     *
     * <p><b>Nothing is written here</b>, and nothing is even set: the ingestion writes these values
     * onto its own findings, in its transaction, a score only where one is known — overwriting with
     * null would erase a score an earlier scan established. The rows are {@code scanning}'s (decision
     * 0029).
     */
    @Override
    public Optional<ScanIngestor.Enrichment> enrich(List<String> identifiers) {
        if (!settings.isEnabled(Setting.ENRICHMENT_ENABLED) || identifiers.isEmpty()) {
            return Optional.empty();
        }

        Map<String, List<String>> spellings = identifiers.stream()
                .collect(Collectors.groupingBy(id -> id.trim().toUpperCase(Locale.ROOT)));
        Map<String, Double> scores = epssScores(spellings);
        Set<String> exploited = exploited(spellings);

        log.info(
                "Enrichment: {}/{} CVE with an EPSS score, {} in the KEV catalogue.",
                scores.size(),
                identifiers.size(),
                exploited.size());
        return Optional.of(new ScanIngestor.Enrichment(scores, exploited));
    }

    /**
     * The stored scores, keyed as the scan spelled each identifier — the ingestion matches on its own
     * spelling, and the file is stored upper-case.
     */
    private Map<String, Double> epssScores(Map<String, List<String>> spellings) {
        if (!epss.synchronised()) {
            log.warn("EPSS scores never synchronised: no finding of this scan gets a score, and none reads as zero.");
            return Map.of();
        }
        Map<String, Double> scores = new HashMap<>();
        for (KnownEpssScore known : epss.scoresOf(spellings.keySet()).values()) {
            spellings.getOrDefault(known.cveId(), List.of()).forEach(spelling -> scores.put(spelling, known.score()));
        }
        return scores;
    }

    /**
     * The identifiers the stored catalogue lists, spelled as the scan spelled them.
     *
     * <p>A refresh never un-flags an issue a scan does not find exploited ({@code IssueSyncService}),
     * so the gap before the first synchronisation costs new issues their flag until it runs, and it
     * re-evaluates them.
     */
    private Set<String> exploited(Map<String, List<String>> spellings) {
        boolean synced = syncs.findById(ThreatIntelSyncEntity.SINGLETON_ID)
                .map(ThreatIntelSyncEntity::getLastSyncedAt)
                .isPresent();
        if (!synced) {
            log.warn("KEV catalogue never synchronised: no finding of this scan can be marked as actively exploited.");
            return Set.of();
        }

        Set<String> exploited = new HashSet<>();
        List<String> lowerCase = spellings.keySet().stream().map(id -> id.toLowerCase(Locale.ROOT)).toList();
        for (List<String> batch : Catalogs.batches(lowerCase, KEV_QUERY_BATCH)) {
            intel.exploitedAmong(batch).forEach(stored ->
                    exploited.addAll(spellings.getOrDefault(stored.toUpperCase(Locale.ROOT), List.of())));
        }
        return exploited;
    }
}
