package com.asmolabs.vectispire.core.services.scanning;

import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.dependencies.DependencyGraph;
import com.asmolabs.vectispire.common.domain.dependencies.Directness;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
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
 *
 * <p><b>What crosses its ports carries no row.</b> Enrichment, end of life, the inventory and the
 * backlog are other modules' work — {@code threatintel}, {@code inventory}, {@code issues} — and they
 * used to receive the scan's {@code FindingEntity} and {@code ScanEntity}, mutable, to fill in place.
 * They receive identifiers and {@link ObservedFinding} records now, and answer values this class
 * applies; the rows, their clipping and their writing are {@code scanning}'s (decision 0029).
 */
@Service
public class ScanIngestor {

    /**
     * The collaborators that reach outside this process.
     *
     * <p>Optional on purpose. Enrichment calls two public catalogues and end-of-life consults a
     * remote one, so an ingestion test that leaves them out stays offline and deterministic
     * instead of depending on somebody else's availability.
     */
    public interface Enricher {
        /**
         * The exploitation scores and the exploited-in-the-wild identifiers among these vulnerability
         * identifiers — or empty when enrichment is switched off, in which case nothing is changed.
         * A score missing from the map is unknown, and leaves the finding's as it was.
         */
        Optional<Enrichment> enrich(List<String> identifiers);
    }

    /** What enrichment found: a score per identifier where one is known, and the exploited ones. */
    public record Enrichment(Map<String, Double> epssScores, Set<String> exploited) {}

    public interface EndOfLifeSource {
        boolean isEnabled();

        /** Absent when the lookup failed, even partly: the type then counts as not scanned. */
        Optional<List<ObservedFinding>> findings(JsonNode sbom);

        String describe(ObservedFinding finding);
    }

    public interface LicenseSource {
        List<ObservedFinding> findings(JsonNode sbom);
    }

    /**
     * Where a completed scan's findings become issues.
     *
     * <p><b>A port, implemented by {@code issues}.</b> The ingestor called {@code IssueSyncService}
     * directly while the backlog read the scans and findings for its history and its sightings —
     * {@code scanning} and {@code issues} used each other. The direction kept is {@code issues} →
     * {@code scanning}: the backlog is derived from what scans observe (decision 0029). Called inside
     * the scan's transaction, which the backlog joins; the delta it announces is queued there too.
     */
    public interface Backlog {
        Reconciliation reconcile(Observation observation);
    }

    /**
     * One scan's findings, as the backlog folds them.
     *
     * @param target {@code null} for a scan attached to neither target, which the backlog refuses
     * @param scannedTypes the types this scan <b>actually looked at</b> — never inferred from the
     *     findings present (decision 0007)
     * @param descriptions advisory text by identifier, for the issues' description
     */
    public record Observation(
            long scanId,
            ScanTarget target,
            List<ObservedFinding> findings,
            Set<FindingType> scannedTypes,
            Map<String, String> descriptions) {}

    /**
     * What folding the findings did to the backlog.
     *
     * @param issueIds the issue each finding is an occurrence of, in the order the findings were given
     */
    public record Reconciliation(int created, int resolved, int reopened, int stillOpen, List<Long> issueIds) {}

    /**
     * Where what a scan says the target is made of goes: its components, read from the SBOM, and its
     * API endpoints and contracts.
     *
     * <p><b>A port, implemented by {@code inventory}.</b> The ingestor called {@code
     * ComponentInventory} and {@code ApiInventoryService} directly, while the inventory reads scans
     * and findings for the licence screen, the SBOM diff and the blast radius: {@code scanning} and
     * {@code inventory} used each other (decision 0029). Declared here, the ingestor hands the
     * inventory what it found and knows nothing of its tables.
     *
     * <p><b>Absent stays absent across it.</b> Each {@code Optional} is what the analyzer reported:
     * empty means "ran, found nothing" and clears that half; absent means "did not run" and leaves
     * the half alone (decision 0007).
     */
    public interface InventorySink {
        /** The SBOM's components for this scan, with their directness from the same document. */
        void components(long scanId, JsonNode sbom, DependencyGraph graph);

        /** The API surface, each half only if its analyzer ran. Never called with both absent. */
        void apis(long scanId, Long repositoryId, Optional<List<ApiEndpoint>> endpoints,
                Optional<List<ApiContract>> contracts);
    }

    private final InventorySink inventory;
    private final Backlog backlog;
    private final Findings findingRows;
    private final Optional<Enricher> enricher;
    private final Optional<EndOfLifeSource> endOfLife;
    private final Optional<LicenseSource> licenses;
    private final Clock clock;

    public ScanIngestor(
            Backlog backlog,
            Findings findingRows,
            Optional<Enricher> enricher,
            Optional<EndOfLifeSource> endOfLife,
            Optional<LicenseSource> licenses,
            InventorySink inventory,
            Clock clock) {
        this.inventory = inventory;
        this.backlog = backlog;
        this.findingRows = findingRows;
        this.enricher = enricher;
        this.endOfLife = endOfLife;
        this.licenses = licenses;
        this.clock = clock;
    }

    /**
     * What ingestion needs from outside this process, fetched before its transaction opens.
     *
     * @param endOfLife the end-of-life findings, or empty when the step did not run — no SBOM,
     *     detection off, or a failed lookup — in which case the type is not declared scanned
     * @param at when they were looked up: their rows are dated then, as they were when the source
     *     built the rows itself
     */
    public record Prepared(Optional<List<ObservedFinding>> endOfLife, Instant at) {}

    /**
     * Performs the remote lookups, <b>outside any transaction</b>.
     *
     * <p>End of life consults a public catalogue, one request per product on a cold cache. Done
     * inside {@link #ingest}, those requests ran while the scan's writing transaction held its
     * rows — the lock that fences a concurrent reclaim included — for as long as the catalogue
     * took to answer. The class promises never to hold a transaction during slow work; this is
     * where that promise is kept.
     */
    public Prepared prepare(ScanEntity scan, ScanArtifacts artifacts) {
        return new Prepared(
                artifacts.sbom().flatMap(sbom -> endOfLife.filter(EndOfLifeSource::isEnabled)
                        .flatMap(source -> source.findings(sbom))),
                clock.instant());
    }

    /** Prepares and ingests in one go — for a caller with no transaction to keep short. */
    @Transactional(propagation = Propagation.MANDATORY)
    public Reconciliation ingest(ScanEntity scan, ScanArtifacts artifacts) {
        return ingest(scan, artifacts, prepare(scan, artifacts));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public Reconciliation ingest(ScanEntity scan, ScanArtifacts artifacts, Prepared prepared) {
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
        artifacts.sbom().ifPresent(sbom -> inventory.components(scan.getId(), sbom, graph));

        // **The two Optionals travel intact, and that is the fix.** They used to be flattened
        // with `orElse(List.of())` here, which handed the inventory "the cataloguer found no
        // contracts" when the truth was "the cataloguer did not run" — and the inventory replaced
        // the repository's contracts with nothing. Same rule as the SBOM three lines above; it was
        // stated there and broken here.
        if (artifacts.apiEndpoints().isPresent() || artifacts.apiContracts().isPresent()) {
            inventory.apis(scan.getId(), scan.getRepoId(), artifacts.apiEndpoints(), artifacts.apiContracts());
        }

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
            Set<String> seenSecrets = new java.util.HashSet<>();
            secrets.forEach(secret -> {
                String locationKey = (secret.file() != null ? secret.file() : "") + ":" + secret.line();
                if (seenSecrets.add(locationKey)) {
                    FindingEntity finding = base(scan, FindingType.SECRET, "gitleaks", secret.rule());
                    // A hardcoded secret is always serious: there is no severity to grade, only a
                    // key to revoke.
                    finding.setSeverity(Severity.HIGH.wireName());
                    finding.setFilePath(secret.file());
                    finding.setLine(secret.line());
                    finding.setDescription(secret.description());
                    findings.add(finding);
                }
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
                // Declared by the rule, never guessed here: most rules declare nothing, and this
                // null is what keeps a finding out of a category nobody claimed.
                finding.setOwaspCategory(result.owaspCategory());
                findings.add(finding);
            });
        });

        // End of life is read from the SBOM. **The type counts as scanned only if detection was
        // switched on, an SBOM exists and the lookup succeeded**: without any of the three,
        // nothing was observed, and declaring it would resolve that type's whole history — "we
        // stopped looking" is not "it is fixed". The third condition was missing: the type was
        // declared before the call, and a catalog outage returned an empty list.
        // Looked up by `prepare`, before the transaction; present only if all three held.
        prepared.endOfLife().ifPresent(found -> {
            scannedTypes.add(FindingType.EOL);
            endOfLife.ifPresent(source -> found.forEach(finding -> {
                if (finding.identifier() != null) {
                    descriptions.put(finding.identifier(), source.describe(finding));
                }
            }));
            found.forEach(finding -> findings.add(row(scan, finding, prepared.at())));
        });

        // Licences are read from the same SBOM, with no network call and no extra tool. The type
        // counts as scanned as soon as an SBOM exists: unlike end of life there is no remote
        // service to reach, so "no findings" genuinely means "no forbidden licence" — including
        // when the list is empty, in which case the old findings should indeed resolve.
        artifacts.sbom().ifPresent(sbom -> licenses.ifPresent(source -> {
            scannedTypes.add(FindingType.LICENSE);
            List<FindingEntity> found = source.findings(sbom).stream()
                    .map(finding -> row(scan, finding, clock.instant()))
                    .toList();
            // Licence findings carry a purl, so the same question — declared or dragged in —
            // applies to them, and the answer changes what can be done about it.
            found.forEach(finding -> setDirectness(
                    finding, graph.of(finding.getPurl(), finding.getPackageName(), finding.getPackageVersion())));
            findings.addAll(found);
        }));

        // **Before the write, not after.** The findings and the issues they open are written below;
        // enriching them afterwards would need a second write outside the scan's transaction, and
        // would leave a window in which the gate sees findings without their exploited-in-the-wild
        // flag — that is, a green verdict on an actively exploited vulnerability.
        enricher.ifPresent(source -> enrich(source, findings));

        // The backlog folds the whole values — the fingerprint's inputs — and queues its delta inside
        // this transaction, never after: a notification written one line later is lost by the very
        // crash the outbox exists to cover.
        Reconciliation result = backlog.reconcile(new Observation(
                scan.getId(),
                scan.target(),
                findings.stream().map(ObservedFinding::of).toList(),
                scannedTypes,
                descriptions));

        // **The findings themselves are written here**, and forgetting it showed on screen: a scan's
        // detail announced eight findings and displayed none. Issues carry a target's history;
        // findings say what one scan observed — the material of the scan detail, of the SARIF export,
        // and of the proof that an issue existed on a given date. Each points at the issue it is an
        // occurrence of, and is clipped to its columns only now, after the fingerprint.
        for (int index = 0; index < findings.size(); index++) {
            FindingEntity finding = findings.get(index);
            finding.setIssueId(result.issueIds().get(index));
            fitToColumns(finding);
        }
        if (!findings.isEmpty()) {
            findingRows.saveAll(findings);
        }

        scan.setNewIssuesCount(result.created());
        scan.setResolvedIssuesCount(result.resolved());
        return result;
    }

    /**
     * Fills the exploitation score and the exploited-in-the-wild flag of the vulnerabilities, with
     * what enrichment found for their identifiers. Only a known score is written — overwriting with
     * {@code null} would erase one obtained on the previous scan, on the day the API happens to be
     * unavailable — and the flag is what the catalogue says, {@code false} for an identifier it does
     * not list.
     */
    private static void enrich(Enricher enricher, List<FindingEntity> findings) {
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
        enricher.enrich(identifiers).ifPresent(found -> vulnerabilities.forEach(finding -> {
            Optional.ofNullable(found.epssScores().get(finding.getIdentifier())).ifPresent(finding::setEpssScore);
            finding.setIsKev(found.exploited().contains(finding.getIdentifier()));
        }));
    }

    /** A finding another step built, as this scan's row: the scan, its instant, not yet exploited. */
    private static FindingEntity row(ScanEntity scan, ObservedFinding observed, Instant at) {
        FindingEntity finding = new FindingEntity();
        finding.setScanId(scan.getId());
        finding.setType(observed.type());
        finding.setSource(observed.source());
        finding.setIdentifier(observed.identifier());
        finding.setSeverity(observed.severity());
        finding.setPackageName(observed.packageName());
        finding.setPackageVersion(observed.packageVersion());
        finding.setPurl(observed.purl());
        finding.setFilePath(observed.filePath());
        finding.setLine(observed.line());
        finding.setIsDirectDependency(observed.directDependency());
        finding.setOwaspCategory(observed.owaspCategory());
        finding.setEpssScore(observed.epssScore());
        finding.setCvssScore(observed.cvssScore());
        finding.setCvssVector(observed.cvssVector());
        finding.setFixState(observed.fixState());
        finding.setFixVersions(observed.fixVersions());
        finding.setLink(observed.link());
        finding.setIsKev(observed.kev());
        finding.setDescription(observed.description());
        finding.setCreatedAt(at);
        return finding;
    }

    /**
     * Clips what a scanner reported to the columns the finding stores it in.
     *
     * <p><b>Why here, and only here.</b> Every value below came from a scanner — a purl, a file
     * path, a fix-version list, an advisory link — and one of them past its column failed the flush
     * of the whole scan: every finding of every type lost, the scan marked failed, for one long
     * purl. The backlog clips the issue's columns for the same reason, and {@code ComponentInventory}
     * its own. Refusing is not an option for a value nobody here typed.
     *
     * <p><b>After the fingerprint, never before it.</b> The identifier, the purl, the package name
     * and the path are the fingerprint's inputs (AGENTS.md: a data contract); the backlog computed
     * every fingerprint from the whole values it was handed before this runs. The stored column is
     * a display copy, and the key is the scanner's own value.
     */
    private static void fitToColumns(FindingEntity finding) {
        finding.setIdentifier(BoundedText.clip(finding.getIdentifier(), 255));
        finding.setPackageName(BoundedText.clip(finding.getPackageName(), 255));
        finding.setPackageVersion(BoundedText.clip(finding.getPackageVersion(), 255));
        finding.setPurl(BoundedText.clip(finding.getPurl(), 255));
        finding.setFilePath(BoundedText.clip(finding.getFilePath(), 500));
        finding.setFixVersions(BoundedText.clip(finding.getFixVersions(), 255));
        finding.setLink(BoundedText.clip(finding.getLink(), 500));
        finding.setCvssVector(BoundedText.clip(finding.getCvssVector(), 255));
        finding.setFixState(BoundedText.clip(finding.getFixState(), 50));
        finding.setSeverity(BoundedText.clip(finding.getSeverity(), 50));
        finding.setDescription(BoundedText.clip(finding.getDescription(), BoundedText.TEXT_MAX));
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
