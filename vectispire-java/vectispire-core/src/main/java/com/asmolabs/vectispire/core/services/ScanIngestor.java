package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.dependencies.DependencyGraph;
import com.asmolabs.vectispire.common.domain.dependencies.Directness;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Clock;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Turning a scan's artifacts into findings, then into issues.
 *
 * <p><b>The set of scanned types is the pivot, and the costliest thing to get wrong.</b> A type
 * belongs to it if and only if the corresponding step <em>actually ran</em>. The distinction is
 * carried by absent-versus-empty in {@link ScanArtifacts}, and this is where it turns into a
 * decision (decision 0007).
 *
 * <p>Getting it wrong resolves a type's entire history in silence — no error, no log line, and
 * nobody notices before the next audit.
 */
@Service
public class ScanIngestor {

    /**
     * The collaborators that reach outside this process.
     *
     * <p>Optional on purpose. Enrichment calls two public catalogues and end-of-life consults a
     * remote one, so an ingestion test that leaves them out stays offline and deterministic
     * instead of depending on somebody else's availability. Notification is optional for a
     * different reason: without a webhook configured, ingestion is exactly what it was.
     */
    public interface Enricher {
        /** Fills the exploitation score and the exploited-in-the-wild flag, in place. */
        void enrich(List<FindingEntity> findings);
    }

    public interface EndOfLifeSource {
        boolean isEnabled();

        List<FindingEntity> findings(ScanEntity scan, JsonNode sbom);

        String describe(FindingEntity finding);
    }

    public interface LicenseSource {
        List<FindingEntity> findings(ScanEntity scan, JsonNode sbom);
    }

    public interface NotificationSink {
        /** Queues the delta inside the caller's transaction, or does nothing. */
        void enqueue(ScanEntity scan, IssueSyncService.SyncResult result);
    }

    private final ComponentInventory inventory;
    private final IssueSyncService sync;
    private final Optional<Enricher> enricher;
    private final Optional<EndOfLifeSource> endOfLife;
    private final Optional<LicenseSource> licenses;
    private final Optional<NotificationSink> notifications;
    private final Clock clock;

    public ScanIngestor(
            IssueSyncService sync,
            Optional<Enricher> enricher,
            Optional<EndOfLifeSource> endOfLife,
            Optional<LicenseSource> licenses,
            Optional<NotificationSink> notifications,
            ComponentInventory inventory,
            Clock clock) {
        this.inventory = inventory;
        this.sync = sync;
        this.enricher = enricher;
        this.endOfLife = endOfLife;
        this.licenses = licenses;
        this.notifications = notifications;
        this.clock = clock;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public IssueSyncService.SyncResult ingest(ScanEntity scan, ScanArtifacts artifacts) {
        List<FindingEntity> findings = new ArrayList<>();
        Set<FindingType> scannedTypes = EnumSet.noneOf(FindingType.class);
        Map<String, String> descriptions = new HashMap<>();

        // **Built once per scan and asked per finding**: the graph is global to the SBOM while
        // findings arrive one package at a time. Without it the directness stayed unknown
        // everywhere — read by the exports, the tickets and the "direct only" filter, and
        // written nowhere.
        DependencyGraph graph = new DependencyGraph(artifacts.sbom().orElse(null));

        // The inventory, written from the same document the graph was built from. Absent when
        // the cataloguer did not run — and absent means the previous scan's inventory is left
        // alone rather than replaced by nothing, exactly as an absent finding list leaves the
        // backlog alone.
        artifacts.sbom().ifPresent(sbom -> inventory.record(scan.getId(), sbom, graph));

        artifacts.dependencies().ifPresent(dependencies -> {
            scannedTypes.add(FindingType.VULNERABILITY);
            dependencies.forEach(dependency -> {
                if (dependency.description() != null) {
                    descriptions.put(dependency.identifier(), dependency.description());
                }
                FindingEntity finding = base(scan, FindingType.VULNERABILITY, "grype", dependency.identifier());
                finding.setSeverity(dependency.severity().wireName());
                finding.setPackageName(dependency.packageName());
                finding.setPackageVersion(dependency.installedVersion());
                finding.setFixVersions(dependency.fixVersions());
                finding.setLink(dependency.referenceUrl());
                finding.setPurl(dependency.purl());
                setDirectness(finding, graph.of(dependency.purl(), dependency.packageName(), dependency.installedVersion()));
                findings.add(finding);
            });
        });

        artifacts.secrets().ifPresent(secrets -> {
            scannedTypes.add(FindingType.SECRET);
            secrets.forEach(secret -> {
                FindingEntity finding = base(scan, FindingType.SECRET, "gitleaks", secret.rule());
                // A hardcoded secret is always serious: there is no severity to grade, only a
                // key to revoke.
                finding.setSeverity(Severity.HIGH.wireName());
                finding.setFilePath(secret.file());
                finding.setLine(secret.line());
                finding.setDescription(secret.description());
                findings.add(finding);
            });
        });

        artifacts.iac().ifPresent(checks -> {
            scannedTypes.add(FindingType.IAC);
            checks.forEach(check -> {
                FindingEntity finding = base(scan, FindingType.IAC, "checkov", check.checkId());
                finding.setSeverity(Severity.MEDIUM.wireName());
                finding.setFilePath(check.file());
                finding.setLine(check.line());
                finding.setDescription(check.checkName());
                finding.setLink(check.guideline());
                findings.add(finding);
            });
        });

        artifacts.sast().ifPresent(results -> {
            // **Both types enter together.** One pass looks for security and for quality;
            // declaring only one would silently resolve the other's entire history.
            scannedTypes.add(FindingType.SAST);
            scannedTypes.add(FindingType.QUALITY);
            results.forEach(result -> {
                // The rule's category decides where it goes — security to the security backlog,
                // the rest to quality, which never fails a build.
                FindingType type = "security".equals(result.category()) ? FindingType.SAST : FindingType.QUALITY;
                FindingEntity finding = base(scan, type, "semgrep", result.ruleId());
                finding.setSeverity(downgradeLowConfidence(result.severity(), result.confidence()).wireName());
                finding.setFilePath(result.file());
                finding.setLine(result.line());
                finding.setDescription(result.message());
                findings.add(finding);
            });
        });

        // End of life is read from the SBOM. **The type counts as scanned only if detection was
        // switched on and an SBOM exists**: without either, nothing was observed, and declaring
        // it would resolve that type's whole history — "we stopped looking" is not "it is
        // fixed".
        artifacts.sbom().ifPresent(sbom -> endOfLife.filter(EndOfLifeSource::isEnabled).ifPresent(source -> {
            scannedTypes.add(FindingType.EOL);
            List<FindingEntity> found = source.findings(scan, sbom);
            found.forEach(finding -> {
                if (finding.getIdentifier() != null) {
                    descriptions.put(finding.getIdentifier(), source.describe(finding));
                }
            });
            findings.addAll(found);
        }));

        // Licences are read from the same SBOM, with no network call and no extra tool. The type
        // counts as scanned as soon as an SBOM exists: unlike end of life there is no remote
        // service to reach, so "no findings" genuinely means "no forbidden licence" — including
        // when the list is empty, in which case the old findings should indeed resolve.
        artifacts.sbom().ifPresent(sbom -> licenses.ifPresent(source -> {
            scannedTypes.add(FindingType.LICENSE);
            List<FindingEntity> found = source.findings(scan, sbom);
            // Licence findings carry a purl, so the same question — declared or dragged in —
            // applies to them, and the answer changes what can be done about it.
            found.forEach(finding -> setDirectness(
                    finding, graph.of(finding.getPurl(), finding.getPackageName(), finding.getPackageVersion())));
            findings.addAll(found);
        }));

        // **Before the write, not after.** The findings are persisted by the sync; enriching
        // them afterwards would need a second write outside the scan's transaction, and would
        // leave a window in which the gate sees findings without their exploited-in-the-wild
        // flag — that is, a green verdict on an actively exploited vulnerability.
        enricher.ifPresent(enrich -> enrich.enrich(findings));

        return sync.sync(scan, findings, scannedTypes, descriptions, result ->
                // **Queued inside the scan's transaction**, never after: a notification written
                // one line later is lost by the very crash the outbox exists to cover.
                notifications.ifPresent(sink -> sink.enqueue(scan, result)));
    }

    /**
     * A low-confidence rule drops one rank; it is not removed.
     *
     * <p>Removing it would make the finding disappear and reappear as new the day the metadata
     * changes — triage lost. Dropping below the default gate threshold gives exactly "visible in
     * the backlog, unable to break a build".
     */
    static Severity downgradeLowConfidence(Severity severity, String confidence) {
        if (!"LOW".equals(confidence)) {
            return severity;
        }
        return switch (severity) {
            case CRITICAL -> Severity.HIGH;
            case HIGH -> Severity.MEDIUM;
            case MEDIUM, LOW -> Severity.LOW;
            case NEGLIGIBLE, UNKNOWN -> severity;
        };
    }

    /**
     * The fields every finding carries, whatever produced it.
     *
     * <p>No fingerprint here, unlike the original: it set one on the object and the column does
     * not exist, so the work was thrown away on every finding of every scan. The identity is
     * computed where it is used, by the reconciliation.
     */
    private FindingEntity base(ScanEntity scan, FindingType type, String source, String identifier) {
        FindingEntity finding = new FindingEntity();
        finding.setScanId(scan.getId());
        finding.setType(type.wireName());
        finding.setSource(source);
        finding.setIdentifier(identifier);
        // Set here: the column is mandatory, and a database default would apply *after* the
        // insert — too late for the entity in memory, which the reconciliation reads.
        finding.setCreatedAt(clock.instant());
        finding.setIsKev(false);
        return finding;
    }

    private static void setDirectness(FindingEntity finding, Directness directness) {
        // Unknown stays unknown: a container scan cannot tell direct from transitive, and
        // writing `false` would claim it could.
        finding.setIsDirectDependency(switch (directness) {
            case DIRECT -> Boolean.TRUE;
            case TRANSITIVE -> Boolean.FALSE;
            case UNKNOWN -> null;
        });
    }
}
