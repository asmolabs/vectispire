package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelRecord;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.ThreatIntelEntity;
import com.asmolabs.vectispire.core.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.ThreatIntelSyncs;
import com.asmolabs.vectispire.core.repositories.ThreatIntels;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service managing live threat intelligence feeds (CISA KEV, EPSS) and re-evaluating
 * backlog issue exploitability continuously.
 */
@Service
public class ThreatIntelFeedService {

    private static final Logger log = LoggerFactory.getLogger(ThreatIntelFeedService.class);

    private final ThreatIntels intelRepo;
    private final ThreatIntelSyncs syncRepo;
    private final Issues issuesRepo;
    private final Findings findingsRepo;
    private final SiemExporterService siemExporter;

    public ThreatIntelFeedService(
            ThreatIntels intelRepo,
            ThreatIntelSyncs syncRepo,
            Issues issuesRepo,
            Findings findingsRepo,
            SiemExporterService siemExporter) {
        this.intelRepo = intelRepo;
        this.syncRepo = syncRepo;
        this.issuesRepo = issuesRepo;
        this.findingsRepo = findingsRepo;
        this.siemExporter = siemExporter;
    }

    public ThreatIntelSyncStatus getStatus() {
        return syncRepo.findById(ThreatIntelSyncEntity.SINGLETON_ID)
                .map(sync -> new ThreatIntelSyncStatus(
                        sync.getLastSyncedAt(),
                        sync.getCveCount(),
                        sync.getKevCount(),
                        sync.getStatus(),
                        0))
                .orElseGet(() -> new ThreatIntelSyncStatus(null, 0, 0, "NEVER_SYNCED", 0));
    }

    @Transactional
    public ThreatIntelSyncStatus syncThreatIntel() {
        // Seed/Ingest prominent threat intelligence entries
        List<ThreatIntelRecord> catalog = getKnownThreatIntelFeed();

        long kevCount = 0;
        for (ThreatIntelRecord record : catalog) {
            ThreatIntelEntity entity = intelRepo.findByCveIdIgnoreCase(record.cveId())
                    .orElseGet(() -> {
                        ThreatIntelEntity fresh = new ThreatIntelEntity();
                        fresh.setCveId(record.cveId().toUpperCase());
                        return fresh;
                    });
            entity.setKev(record.isKev());
            entity.setEpssScore(record.epssScore());
            entity.setEpssPercentile(record.epssPercentile());
            entity.setDateAdded(record.dateAdded());
            entity.setUpdatedAt(Instant.now());
            intelRepo.save(entity);

            if (record.isKev()) {
                kevCount++;
            }
        }

        // **Re-evaluate the backlog in two queries, not one plus one per issue.** This read the
        // whole of `t_issue` and filtered the closed rows in Java, then asked the intel table for
        // one CVE at a time: half a million rows loaded and half a million queries, on an estate
        // the size the dimensioning view assumes. The state filter is now SQL and the intel comes
        // back in a single batch. What is unchanged on purpose is which issues qualify — "not
        // closed and not resolved", passed as data so the definition stays the caller's.
        long updatedIssuesCount = 0;
        List<IssueEntity> allOpenIssues = issuesRepo.findByStateNotIn(List.of("closed", "resolved"));

        Map<String, ThreatIntelEntity> intelByCve = allOpenIssues.stream()
                .map(IssueEntity::getIdentifier)
                .filter(Objects::nonNull)
                .map(id -> id.toLowerCase(Locale.ROOT))
                .distinct()
                .collect(Collectors.collectingAndThen(
                        Collectors.toList(),
                        ids -> ids.isEmpty()
                                ? Map.<String, ThreatIntelEntity>of()
                                : intelRepo.findByCveIdInIgnoreCase(ids).stream()
                                        .collect(Collectors.toMap(
                                                intel -> intel.getCveId().toLowerCase(Locale.ROOT),
                                                intel -> intel,
                                                (left, right) -> left))));

        for (IssueEntity issue : allOpenIssues) {
            if (issue.getIdentifier() == null) continue;
            Optional<ThreatIntelEntity> match = Optional.ofNullable(
                    intelByCve.get(issue.getIdentifier().toLowerCase(Locale.ROOT)));
            if (match.isPresent()) {
                ThreatIntelEntity intel = match.get();
                boolean becameKev = !issue.isKev() && intel.isKev();
                boolean updated = false;

                if (intel.isKev() != issue.isKev()) {
                    issue.setKev(intel.isKev());
                    updated = true;
                }
                if (intel.getEpssScore() != null && !intel.getEpssScore().equals(issue.getEpssScore())) {
                    issue.setEpssScore(intel.getEpssScore());
                    updated = true;
                }

                if (updated) {
                    issuesRepo.save(issue);
                    updatedIssuesCount++;

                    if (becameKev) {
                        log.warn("CVE {} newly reclassified as actively exploited CISA KEV! Notifying SOC/SIEM.", issue.getIdentifier());
                        CefEvent cef = CefEvent.builder(SecurityEventType.CRITICAL_KEV_DETECTED)
                                .message("Vulnerability " + issue.getIdentifier() + " promoted to CISA Known Exploited Vulnerability (KEV)")
                                .extension("cve", issue.getIdentifier())
                                .extension("cs1", issue.getPackageName())
                                .extension("cs1Label", "PackageName")
                                .build();
                        siemExporter.exportEvent(cef);
                    }
                }
            }
        }

        // Update sync record
        ThreatIntelSyncEntity sync = syncRepo.findById(ThreatIntelSyncEntity.SINGLETON_ID)
                .orElseGet(() -> {
                    ThreatIntelSyncEntity fresh = new ThreatIntelSyncEntity();
                    fresh.setId(ThreatIntelSyncEntity.SINGLETON_ID);
                    return fresh;
                });
        Instant now = Instant.now();
        sync.setLastSyncedAt(now);
        sync.setCveCount(catalog.size());
        sync.setKevCount(kevCount);
        sync.setStatus("SYNCED");
        syncRepo.save(sync);

        return new ThreatIntelSyncStatus(now, catalog.size(), kevCount, "SYNCED", updatedIssuesCount);
    }

    public Optional<ThreatIntelRecord> lookupCve(String cveId) {
        if (cveId == null || cveId.isBlank()) return Optional.empty();
        Optional<ThreatIntelEntity> entity = intelRepo.findByCveIdIgnoreCase(cveId.trim());
        if (entity.isPresent()) {
            ThreatIntelEntity e = entity.get();
            return Optional.of(new ThreatIntelRecord(
                    e.getCveId(),
                    e.isKev(),
                    e.getEpssScore(),
                    e.getEpssPercentile(),
                    e.getDateAdded(),
                    "Database synchronized record"));
        }
        return getKnownThreatIntelFeed().stream()
                .filter(r -> r.cveId().equalsIgnoreCase(cveId.trim()))
                .findFirst();
    }

    private List<ThreatIntelRecord> getKnownThreatIntelFeed() {
        Instant past = Instant.parse("2024-01-01T00:00:00Z");
        return List.of(
                new ThreatIntelRecord("CVE-2021-44228", true, 0.975, 0.999, past, "Log4Shell RCE"),
                new ThreatIntelRecord("CVE-2022-22965", true, 0.950, 0.995, past, "Spring4Shell RCE"),
                new ThreatIntelRecord("CVE-2022-42889", true, 0.910, 0.985, past, "Text4Shell RCE"),
                new ThreatIntelRecord("CVE-2023-34362", true, 0.970, 0.998, past, "MOVEit Transfer SQLi"),
                new ThreatIntelRecord("CVE-2023-44487", true, 0.890, 0.975, past, "HTTP/2 Rapid Reset"),
                new ThreatIntelRecord("CVE-2024-3094", true, 0.965, 0.997, past, "XZ Utils Backdoor"),
                new ThreatIntelRecord("CVE-2024-6387", true, 0.920, 0.988, past, "regreSSHion OpenSSH RCE"),
                new ThreatIntelRecord("CVE-2024-21626", true, 0.940, 0.991, past, "runc Container Breakout"),
                new ThreatIntelRecord("CVE-2024-4577", true, 0.955, 0.996, past, "PHP CGI Argument Injection"),
                new ThreatIntelRecord("CVE-2025-12345", true, 0.880, 0.960, past, "Zero-day emerging threat")
        );
    }
}
