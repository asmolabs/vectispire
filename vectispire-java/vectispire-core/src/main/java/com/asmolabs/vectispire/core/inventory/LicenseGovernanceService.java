package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleTarget;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.licenses.LicenseConflictMatrix;
import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.licenses.LicensePolicy;
import com.asmolabs.vectispire.common.domain.licenses.LicenseRiskCategory;
import com.asmolabs.vectispire.common.domain.licenses.LicenseSummary;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentName;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.inventory.persistence.LicensePolicyRepository;
import com.asmolabs.vectispire.core.inventory.persistence.LicensePolicyEntity;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanFindingView;
import com.asmolabs.vectispire.core.targets.ContainerView;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Service managing open source license inventory, copyleft risk classification, and policy compliance.
 */
@Service
public class LicenseGovernanceService {

    private static final Logger log = LoggerFactory.getLogger(LicenseGovernanceService.class);

    private final LicensePolicyRepository policyRepo;
    private final ComponentRepository componentsRepo;
    private final ScanCatalog scansRepo;
    private final TargetCatalog targets;
    private final ObjectMapper objectMapper;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;

    /**
     * Each target's licences, counted — see {@link #violationsByTarget}. Kept per target for every
     * reader, never handed out: judged by the policy and narrowed to the reader at each read.
     */
    private final Map<Owner, Tally> tallies = new ConcurrentHashMap<>();

    public LicenseGovernanceService(
            LicensePolicyRepository policyRepo,
            ComponentRepository componentsRepo,
            ScanCatalog scansRepo,
            TargetCatalog targets,
            ObjectMapper objectMapper,
            AuditLogService audit,
            TransactionTemplate transactions) {
        this.policyRepo = policyRepo;
        this.componentsRepo = componentsRepo;
        this.scansRepo = scansRepo;
        this.targets = targets;
        this.objectMapper = objectMapper;
        this.audit = audit;
        this.transactions = transactions;
    }

    public LicensePolicy getPolicy() {
        return policyRepo.findById(LicensePolicyEntity.SINGLETON_ID)
                .map(this::toDomainPolicy)
                .orElseGet(LicensePolicy::defaultPolicy);
    }

    /**
     * Stores the policy, then audits it.
     *
     * <p>Through a {@link TransactionTemplate} rather than by calling the annotated method below:
     * through {@code this} the annotation is bypassed, and the audit entry has to follow the commit
     * rather than sit inside it — it opens its own transaction, and inside the write's it would
     * describe a policy that may still roll back.
     */
    public LicensePolicy updatePolicy(LicensePolicy policy, RequestActor actor) {
        if (policy == null) {
            throw new InvalidInputException("A licence policy is required.");
        }
        // The record has already dropped nulls and upper-cased the identifiers. What it cannot
        // decide is what the storage can hold: the lists are stored comma-joined, so an entry
        // holding a comma would come back as two, and each list is a `text` column.
        requireStorable(policy.explicitlyAllowedLicenses(), "allowed");
        requireStorable(policy.explicitlyDisallowedLicenses(), "disallowed");
        LicensePolicy updated = transactions.execute(status -> updatePolicy(policy));
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED,
                "license_policy",
                "Updated open source license compliance policy (disallowed=" + policy.disallowedCategories() + ")"));
        return updated;
    }

    private static void requireStorable(Set<String> licences, String which) {
        licences.stream().filter(licence -> licence.contains(",")).findFirst().ifPresent(licence -> {
            throw new InvalidInputException("\"" + licence + "\" contains a comma: list each "
                    + which + " licence as an entry of its own.");
        });
        BoundedText.within(String.join(",", licences), BoundedText.TEXT_MAX, "The " + which + " licence list");
    }

    @Transactional
    public LicensePolicy updatePolicy(LicensePolicy policy) {
        LicensePolicyEntity entity = policyRepo.findById(LicensePolicyEntity.SINGLETON_ID)
                .orElseGet(() -> {
                    LicensePolicyEntity fresh = new LicensePolicyEntity();
                    fresh.setId(LicensePolicyEntity.SINGLETON_ID);
                    return fresh;
                });

        String disallowedCats = policy.disallowedCategories().stream()
                .map(Enum::name)
                .collect(Collectors.joining(","));
        entity.setDisallowedCategories(disallowedCats);
        entity.setAllowedLicenses(String.join(",", policy.explicitlyAllowedLicenses()));
        entity.setDisallowedLicenses(String.join(",", policy.explicitlyDisallowedLicenses()));
        entity.setUpdatedAt(Instant.now());

        policyRepo.save(entity);
        return policy;
    }

    /**
     * One target's inventory, for a caller that checked the target — the scorecard, whose service
     * refused a hidden one first.
     *
     * <p><b>The proof, not two ids.</b> This was {@code getInventory(repoId, containerId)}, public
     * and unfiltered, beside the forms that narrow to an allowance: any caller naming a target read
     * its dependencies whoever it was acting for. The estate's form went with it — the portfolio
     * reads {@link #getInventory(Visibility, Long, Long)} with no target, which narrows.
     */
    public List<LicenseEntry> getInventory(VisibleTarget<?> checked) {
        return switch (checked.target()) {
            case ScanTarget.Repository repository -> inventoryOf(repository.id(), null);
            case ScanTarget.Container container -> inventoryOf(null, container.id());
        };
    }

    /** Scans per component lookup: far under every engine's bind-parameter ceiling. */
    private static final int SCAN_BATCH = 1_000;

    /**
     * The licence inventory, <b>read for the target asked about rather than for the estate</b>.
     *
     * <p><b>The filter arrived and was then ignored by every read.</b> It read every scan, every
     * component and every finding in the deployment and applied {@code repoIdFilter} afterwards
     * in Java. A scan row carries its whole SBOM payload — megabytes of JSON apiece — so asking
     * for one repository's licences parsed the estate's, and the security scorecard did exactly
     * that on every call: it asked for the unfiltered inventory and then kept one target's rows.
     *
     * <p>The scans are selected first and everything else is keyed to them, which is the shape
     * the method already had in Java and now has in SQL.
     */
    private List<LicenseEntry> inventoryOf(Long repoIdFilter, Long containerIdFilter) {
        List<ScanCatalog.ScanSbom> selected;
        if (repoIdFilter != null) {
            selected = scansRepo.sbomsOfTargets(List.of(new ScanTarget.Repository(repoIdFilter)));
        } else if (containerIdFilter != null) {
            selected = scansRepo.sbomsOfTargets(List.of(new ScanTarget.Container(containerIdFilter)));
        } else {
            selected = scansRepo.sboms();
        }
        // An image's inventory leaves out the SBOM of a scan that also names a repository — that scan
        // is the repository's — and has always kept its components and findings, keyed to the
        // repository all the same.
        Predicate<ScanCatalog.ScanSbom> readsSbom = repoIdFilter == null && containerIdFilter != null
                ? scan -> scan.repoId() == null
                : scan -> true;
        return named(selected, readsSbom);
    }

    /** The entries of these scans, judged by the policy in force and named after their targets. */
    private List<LicenseEntry> named(List<ScanCatalog.ScanSbom> selected, Predicate<ScanCatalog.ScanSbom> readsSbom) {
        LicensePolicy policy = getPolicy();

        Map<Long, RepositoryView> repos = targets.repositories().stream()
                .collect(Collectors.toMap(RepositoryView::id, r -> r, (a, b) -> a));

        Map<Long, ContainerView> containers = targets.containers().stream()
                .collect(Collectors.toMap(ContainerView::id, c -> c, (a, b) -> a));

        Function<ScanCatalog.ScanSbom, String> nameOf = scan -> scan.repoId() != null && repos.containsKey(scan.repoId())
                ? repos.get(scan.repoId()).name()
                : (scan.containerId() != null && containers.containsKey(scan.containerId())
                        ? containers.get(scan.containerId()).imageName() + ":" + containers.get(scan.containerId()).tag()
                        : "General");
        return new ArrayList<>(entries(selected, readsSbom, policy, nameOf).values());
    }

    /**
     * The entries of these scans, keyed by target, name and version.
     *
     * <p><b>Scans and findings in identifier order</b>, so that of two scans of one target declaring
     * the same component under different licences the newer one is kept — which used to be decided by
     * the order of a hash map's buckets, and so by how many scans the read happened to hold. The
     * licence tallies count one target's scans where the estate's inventory reads every scan, and the
     * two must keep the same entry; an order that depended on the batch could not promise it. The
     * component rows come in scan and row order for the same reason, the first naming an entry its
     * SBOM lacks giving the entry its purl.
     *
     * <p>Each entry's key begins with its target, so the scans of one target produce the same entries
     * whatever other scans are read with them: the estate's inventory narrowed to a target is that
     * target's — and a reader's inventory may be read from their targets' scans alone.
     */
    private Map<String, LicenseEntry> entries(
            Collection<ScanCatalog.ScanSbom> selected,
            Predicate<ScanCatalog.ScanSbom> readsSbom,
            LicensePolicy policy,
            Function<ScanCatalog.ScanSbom, String> nameOf) {
        Map<String, LicenseEntry> entryMap = new HashMap<>();
        Map<Long, ScanCatalog.ScanSbom> scans = new TreeMap<>();
        selected.forEach(scan -> scans.putIfAbsent(scan.id(), scan));

        // 1. Ingest real licenses from Scan SBOMs (Syft / CycloneDX)
        for (ScanCatalog.ScanSbom scan : scans.values()) {
            if (!readsSbom.test(scan)) {
                continue;
            }

            Long targetId = scan.repoId() != null ? scan.repoId() : scan.containerId();
            String targetKind = scan.repoId() != null ? "repository" : (scan.containerId() != null ? "container" : "general");

            if (scan.sbom() != null && !scan.sbom().isBlank()) {
                try {
                    JsonNode root = objectMapper.readTree(scan.sbom());
                    JsonNode artifacts = root.path("artifacts");
                    if (artifacts.isArray()) {
                        String targetName = nameOf.apply(scan);
                        for (JsonNode artifact : artifacts) {
                            String name = artifact.path("name").asText(null);
                            if (name == null || name.isBlank()) continue;
                            String version = artifact.path("version").asText(null);
                            String purl = artifact.path("purl").asText(null);

                            String license = extractLicenseFromSbom(artifact);
                            if (license == null || license.isBlank() || "UNKNOWN".equalsIgnoreCase(license)) {
                                license = UNDECLARED;
                            }

                            LicenseRiskCategory risk = LicenseRiskCategory.classify(license);
                            boolean compliant = policy.isCompliant(license, risk);
                            String violationReason = compliant ? null : "License " + license + " is forbidden under active compliance policy (" + risk + ")";

                            String key = targetKind + ":" + targetId + ":" + name + ":" + (version != null ? version : "");
                            entryMap.put(key, new LicenseEntry(
                                    name,
                                    version != null ? version : "unknown",
                                    purl,
                                    license,
                                    risk,
                                    compliant,
                                    violationReason,
                                    targetId,
                                    targetKind,
                                    targetName));
                        }
                    }
                } catch (Exception unreadable) {
                    // Logged, not swallowed: an SBOM that no longer parses took every licence of
                    // its scan out of the inventory with nothing to say why.
                    log.warn("Scan {}: SBOM unreadable, its licences are missing from the inventory: {}",
                            scan.id(), unreadable.getMessage());
                }
            }
        }

        // 2. Check components from CycloneDX/Component table for any scan not covered by full SBOM JSON
        // A thousand scans per statement: the portfolio's inventory reads every scan of the estate,
        // and one bind parameter each is refused by the PostgreSQL driver past 65,535.
        List<Long> scanIds = List.copyOf(scans.keySet());
        List<ComponentName> components = new ArrayList<>();
        for (int from = 0; from < scanIds.size(); from += SCAN_BATCH) {
            components.addAll(componentsRepo.namesOfScans(scanIds.subList(from, Math.min(from + SCAN_BATCH, scanIds.size()))));
        }
        for (ComponentName comp : components) {
            ScanCatalog.ScanSbom scan = comp.scanId() != null ? scans.get(comp.scanId()) : null;
            if (scan == null) continue;

            Long targetId = scan.repoId() != null ? scan.repoId() : scan.containerId();
            String targetKind = scan.repoId() != null ? "repository" : (scan.containerId() != null ? "container" : "general");

            String key = targetKind + ":" + targetId + ":" + comp.name() + ":" + (comp.version() != null ? comp.version() : "");
            if (!entryMap.containsKey(key)) {
                String inferredLicense = UNDECLARED;
                LicenseRiskCategory risk = LicenseRiskCategory.classify(inferredLicense);
                boolean compliant = policy.isCompliant(inferredLicense, risk);
                String violationReason = compliant ? null : "License " + inferredLicense + " is forbidden under active compliance policy (" + risk + ")";

                entryMap.put(key, new LicenseEntry(
                        comp.name(),
                        comp.version() != null ? comp.version() : "unknown",
                        comp.purl(),
                        inferredLicense,
                        risk,
                        compliant,
                        violationReason,
                        targetId,
                        targetKind,
                        nameOf.apply(scan)));
            }
        }

        // 3. Check direct license findings from scanners (Trivy license scanner)
        List<ScanFindingView> licenseFindings = scans.isEmpty()
                ? List.of()
                : scansRepo.licenseFindings(scans.keySet()).stream()
                        .sorted(Comparator.comparing(ScanFindingView::scanId, Comparator.nullsFirst(Comparator.naturalOrder()))
                                .thenComparing(ScanFindingView::id, Comparator.nullsFirst(Comparator.naturalOrder())))
                        .toList();

        for (ScanFindingView finding : licenseFindings) {
            ScanCatalog.ScanSbom scan = finding.scanId() != null ? scans.get(finding.scanId()) : null;
            if (scan == null) continue;

            Long targetId = scan.repoId() != null ? scan.repoId() : scan.containerId();
            String targetKind = scan.repoId() != null ? "repository" : (scan.containerId() != null ? "container" : "general");

            String license = finding.identifier() != null ? finding.identifier() : "UNKNOWN";
            LicenseRiskCategory risk = LicenseRiskCategory.classify(license);
            boolean compliant = policy.isCompliant(license, risk);
            String violationReason = compliant ? null : "License " + license + " is forbidden under active compliance policy (" + risk + ")";

            String key = targetKind + ":" + targetId + ":" + (finding.packageName() != null ? finding.packageName() : "unknown") + ":" + (finding.packageVersion() != null ? finding.packageVersion() : "");
            entryMap.put(key, new LicenseEntry(
                    finding.packageName() != null ? finding.packageName() : "unknown",
                    finding.packageVersion() != null ? finding.packageVersion() : "unknown",
                    finding.purl(),
                    license,
                    risk,
                    compliant,
                    violationReason,
                    targetId,
                    targetKind,
                    nameOf.apply(scan)));
        }

        return entryMap;
    }

    /**
     * How many entries of each target's inventory the policy refuses, for every target {@code allowed}
     * permits that holds a scan — the figure the dashboard's ranking charges five points apiece, equal
     * to counting the refused entries of {@link #getInventory(Visibility, Long, Long)} target by target.
     *
     * <p><b>Why not that count.</b> The ranking read the estate's inventory on every load of the home
     * page: every scan row with its payloads, every SBOM parsed, every component row of every scan ever
     * made — 105,000 entities and about 420 ms for two hundred targets of two scans and 250 components,
     * and as much for a reader granted five of them, since the narrowing came after the read. It grows
     * with the history, not with what changed.
     *
     * <p><b>Each target's licences are tallied once and kept until its scans move</b>: how many entries
     * declare each licence, which the policy then judges at every read — a policy change is seen at
     * once, and a tally is a handful of numbers rather than an inventory. Whether a target's scans moved
     * is read every time, from the database, as counts: the {@link ScanCatalog.ScanCensus} of its scans,
     * and how many of those holding an SBOM have component rows. What decides a target's inventory
     * changes only with one of them —
     * <ul>
     *   <li>its scans are added (a new identifier), and deleted only with the target;
     *   <li>its SBOMs, licence findings and components are written by the write that takes a scan out
     *       of its running status, once (a status count moves);
     *   <li>an SBOM is dropped by the retention purge (the SBOM count moves), after which the scan's
     *       components speak for it;
     *   <li>the inventory's backfill gives components to a scan holding an SBOM and none (the count of
     *       indexed SBOM scans moves).
     * </ul>
     * A writer that changed any of these in another way would leave a tally behind it: the proof is
     * {@code LicenceTalliesDatabaseTest}, one case per line above. The scans attached to no target are
     * tallied together under the same census, for the readers of the whole estate.
     *
     * <p><b>Exact on every instance, and never one reader's estate served to another.</b> The census is
     * read before the inventory it vouches for, so a tally can only be newer than its stamp, and a
     * newer census recounts it. A tally belongs to a target, not to a reader: whoever asks receives the
     * targets they may see and nothing else, and the recount reads those alone. Nothing expires on a
     * clock — a tally is right or recounted — and a target whose scans are gone leaves the map.
     */
    public Map<ScanTarget, Long> violationsByTarget(Visibility allowed) {
        LicensePolicy policy = getPolicy();
        Map<ScanTarget, Long> violations = new HashMap<>();
        talliesWithin(allowed, policy).forEach((owner, tally) -> {
            if (owner.target() != null) {
                violations.put(owner.target(), tally.refusedBy(policy));
            }
        });
        return violations;
    }

    /**
     * How many entries of the inventory {@code allowed} sees the policy refuses — the portfolio
     * scorecard's licence term ({@link #violations}'s {@code total}), equal to counting the refused
     * entries of {@link #getInventory(Visibility, Long, Long)} with no target, and read off the tallies
     * {@link #violationsByTarget} keeps.
     *
     * <p>The scans attached to no target count for a reader who sees the whole estate, as their entries
     * do in that inventory, and for nobody else.
     */
    public long violationsWithin(Visibility allowed) {
        return violations(allowed).total();
    }

    /**
     * Both counts the portfolio scorecard reads, from one read of the tallies: each target's, as
     * {@link #violationsByTarget} gives them, and the whole allowance's, as {@link #violationsWithin}
     * does — the scans attached to no target included for a reader of the whole estate.
     *
     * @param total at least the sum of {@code byTarget}
     */
    public record Violations(Map<ScanTarget, Long> byTarget, long total) {}

    /** {@link #violationsByTarget} and {@link #violationsWithin} at once, the census read once. */
    public Violations violations(Visibility allowed) {
        LicensePolicy policy = getPolicy();
        Map<ScanTarget, Long> byTarget = new HashMap<>();
        long total = 0;
        for (Map.Entry<Owner, Tally> tally : talliesWithin(allowed, policy).entrySet()) {
            long refused = tally.getValue().refusedBy(policy);
            total += refused;
            if (tally.getKey().target() != null) {
                byTarget.put(tally.getKey().target(), refused);
            }
        }
        return new Violations(byTarget, total);
    }

    /**
     * Whose a tally is: a target, or — {@code target} null — the scans attached to none, which
     * {@link Visibility#permits} grants an unrestricted reader alone.
     */
    private record Owner(ScanTarget target) {}

    /** The licences of one owner's inventory, counted, and the census they were counted under. */
    private record Tally(Stamp stamp, Map<String, Long> licences) {

        long refusedBy(LicensePolicy policy) {
            long refused = 0;
            for (Map.Entry<String, Long> licence : licences.entrySet()) {
                if (!policy.isCompliant(licence.getKey(), LicenseRiskCategory.classify(licence.getKey()))) {
                    refused += licence.getValue();
                }
            }
            return refused;
        }
    }

    /** What a target's inventory is made of, in counts — see {@link #violationsByTarget}. */
    private record Stamp(ScanCatalog.ScanCensus scans, long indexedSboms) {}

    /**
     * The tallies of every owner {@code allowed} permits that holds a scan, those whose census moved
     * counted again first.
     */
    private Map<Owner, Tally> talliesWithin(Visibility allowed, LicensePolicy policy) {
        // Read first: the inventory read after it can only be as new or newer.
        Map<Owner, Stamp> stamps = stamps();
        tallies.keySet().retainAll(stamps.keySet());

        List<Owner> stale = new ArrayList<>();
        for (Map.Entry<Owner, Stamp> stamp : stamps.entrySet()) {
            if (allowed.permits(stamp.getKey().target())) {
                Tally kept = tallies.get(stamp.getKey());
                if (kept == null || !kept.stamp().equals(stamp.getValue())) {
                    stale.add(stamp.getKey());
                }
            }
        }
        if (!stale.isEmpty()) {
            recount(stale, stamps, policy);
        }

        Map<Owner, Tally> within = new HashMap<>();
        for (Owner owner : stamps.keySet()) {
            Tally tally = tallies.get(owner);
            if (tally != null && allowed.permits(owner.target())) {
                within.put(owner, tally);
            }
        }
        return within;
    }

    private Map<Owner, Stamp> stamps() {
        ScanCatalog.Census census = scansRepo.census();
        Map<Long, Owner> sbomScans = new HashMap<>();
        scansRepo.withSbom().forEach(scan -> sbomScans.put(scan.id(), new Owner(scan.target())));
        // An index lookup on the scan column per thousand: only the scans still holding an SBOM, which
        // the retention purge bounds, are asked.
        Map<Owner, Long> indexed = new HashMap<>();
        List<Long> ids = List.copyOf(sbomScans.keySet());
        for (int from = 0; from < ids.size(); from += SCAN_BATCH) {
            componentsRepo.indexedAmong(ids.subList(from, Math.min(from + SCAN_BATCH, ids.size())))
                    .forEach(id -> indexed.merge(sbomScans.get(id), 1L, Long::sum));
        }
        Map<Owner, Stamp> stamps = new HashMap<>();
        census.byTarget().forEach((target, scans) -> {
            Owner owner = new Owner(target);
            stamps.put(owner, new Stamp(scans, indexed.getOrDefault(owner, 0L)));
        });
        if (census.untargeted().scans() > 0) {
            Owner none = new Owner(null);
            stamps.put(none, new Stamp(census.untargeted(), indexed.getOrDefault(none, 0L)));
        }
        return stamps;
    }

    /**
     * Counts again the owners whose census moved — their scans alone, through the very computation
     * the inventory runs, so that a tally and the inventory cannot disagree about an entry.
     */
    private void recount(List<Owner> stale, Map<Owner, Stamp> stamps, LicensePolicy policy) {
        Map<Owner, Map<String, Long>> counted = new HashMap<>();
        stale.forEach(owner -> counted.put(owner, new HashMap<>()));
        List<ScanTarget> targetsOf = stale.stream().map(Owner::target).filter(java.util.Objects::nonNull).toList();
        List<ScanCatalog.ScanSbom> read = new ArrayList<>(scansRepo.sbomsOfTargets(targetsOf));
        if (counted.containsKey(new Owner(null))) {
            read.addAll(scansRepo.sbomsOfUntargeted());
        }
        // A scan naming an image and a repository is read for either and keyed to the repository, as
        // the estate's inventory keys it: its entries count for the repository's tally, or for none
        // when the repository's is not being recounted — and then it is not even parsed.
        read.removeIf(scan -> !counted.containsKey(new Owner(scan.target())));
        for (LicenseEntry entry : entries(read, scan -> true, policy, scan -> null).values()) {
            Owner owner = new Owner(targetOf(entry));
            if (counted.containsKey(owner)) {
                counted.get(owner).merge(entry.license(), 1L, Long::sum);
            }
        }
        counted.forEach((owner, licences) -> tallies.put(owner, new Tally(stamps.get(owner), Map.copyOf(licences))));
    }

    /**
     * The inventory a reader may see: a named target's, or the estate's narrowed to their allowance.
     *
     * <p><b>A component inventory is a map of someone's dependencies and their licences.</b> The
     * route used to narrow it itself, after asking this service for the unfiltered one; the
     * narrowing is the decision, and it belongs beside the read. A named target the reader may not
     * see is still the route's to refuse first, with the one sentence {@code Visibilities} gives —
     * this module's services do not use {@code access} — and a route that forgot would get it
     * answered empty here rather than whole.
     *
     * <p><b>A restricted reader's is read from their targets' scans</b>, not from the estate's narrowed
     * afterwards: every entry is keyed to the target its scan is attributed to, so the scans attributed
     * to another target only ever produced entries the narrowing dropped. It read every scan, component
     * and licence finding of the deployment for a reader granted five targets. A reader who sees
     * everything still reads the history — the list is one row per component of every scan — through
     * the columns it needs rather than the rows.
     */
    public List<LicenseEntry> getInventory(Visibility allowed, Long repoIdFilter, Long containerIdFilter) {
        if (repoIdFilter == null && containerIdFilter == null && allowed instanceof Visibility.Only only) {
            List<ScanCatalog.ScanSbom> theirs = new ArrayList<>(scansRepo.sbomsOfTargets(only.targets()));
            theirs.removeIf(scan -> !allowed.permits(scan.target()));
            return visibleOnly(allowed, named(theirs, scan -> true));
        }
        return visibleOnly(allowed, inventoryOf(repoIdFilter, containerIdFilter));
    }

    /**
     * The summary of a named target, or of the estate for a reader who sees all of it.
     *
     * <p><b>Refused, not narrowed, for a restricted reader asking about the estate</b>: the route
     * has always answered that with a 404 rather than with their own targets' figures. The evidence
     * bundle, which narrows, reads {@link #getSummary(Visibility)}.
     *
     * <p>The estate's is counted off the tallies, as {@link #getSummary(Visibility)} is; a named
     * target's is its inventory's, read for it.
     *
     * @throws NotFoundException for a restricted reader naming no target — 404, never 403
     */
    public LicenseSummary getSummary(Visibility allowed, Long repoIdFilter, Long containerIdFilter) {
        requireEstateOrTarget(allowed, repoIdFilter, containerIdFilter);
        if (repoIdFilter == null && containerIdFilter == null) {
            return getSummary(allowed);
        }
        return summarize(getInventory(allowed, repoIdFilter, containerIdFilter));
    }

    /**
     * Refuses an aggregate a restricted reader must not receive whole.
     *
     * <p>A call with no target is fine for a reader who sees everything and refused for one who does
     * not. The summary is counts and a conflict names its target without an id, so neither can be
     * narrowed by the route after the fact; answering the estate's is the leak.
     */
    private static void requireEstateOrTarget(Visibility allowed, Long repoIdFilter, Long containerIdFilter) {
        if (repoIdFilter == null && containerIdFilter == null && !(allowed instanceof Visibility.Everything)) {
            throw new NotFoundException("Not found.");
        }
    }

    private static List<LicenseEntry> visibleOnly(Visibility allowed, List<LicenseEntry> inventory) {
        return inventory.stream().filter(entry -> allowed.permits(targetOf(entry))).toList();
    }

    /**
     * The summary over the targets {@code allowed} permits, for a reader that has an allowance
     * rather than a target — the evidence bundle, handed a credential restricted to some targets.
     *
     * <p>An entry attached to no target ({@code general}) is permitted by an unrestricted allowance
     * only, which is how {@link Visibility#permits} treats a missing target everywhere else.
     *
     * <p><b>Counted off the tallies</b> {@link #violationsByTarget} keeps: a summary is counts by
     * licence — how many entries, how many distinct licences, how many refused, how many in each risk
     * category — which is what a tally holds, so it equals summarising the inventory narrowed to the
     * allowance without reading it.
     */
    public LicenseSummary getSummary(Visibility allowed) {
        LicensePolicy policy = getPolicy();
        Map<String, Long> licences = new HashMap<>();
        talliesWithin(allowed, policy).values()
                .forEach(tally -> tally.licences().forEach((licence, count) -> licences.merge(licence, count, Long::sum)));

        Map<LicenseRiskCategory, Long> breakdown = new EnumMap<>(LicenseRiskCategory.class);
        for (LicenseRiskCategory cat : LicenseRiskCategory.values()) {
            breakdown.put(cat, 0L);
        }
        long entries = 0;
        long unique = 0;
        long refused = 0;
        for (Map.Entry<String, Long> licence : licences.entrySet()) {
            LicenseRiskCategory risk = LicenseRiskCategory.classify(licence.getKey());
            breakdown.merge(risk, licence.getValue(), Long::sum);
            entries += licence.getValue();
            if (!licence.getKey().isBlank()) {
                unique++;
            }
            if (!policy.isCompliant(licence.getKey(), risk)) {
                refused += licence.getValue();
            }
        }
        return new LicenseSummary(entries, unique, refused, breakdown);
    }

    private static ScanTarget targetOf(LicenseEntry entry) {
        if (entry.targetId() == null) {
            return null;
        }
        return switch (entry.targetKind()) {
            case "repository" -> new ScanTarget.Repository(entry.targetId());
            case "container" -> new ScanTarget.Container(entry.targetId());
            default -> null;
        };
    }

    private static LicenseSummary summarize(List<LicenseEntry> inventory) {
        Map<LicenseRiskCategory, Long> breakdown = new EnumMap<>(LicenseRiskCategory.class);
        for (LicenseRiskCategory cat : LicenseRiskCategory.values()) {
            breakdown.put(cat, 0L);
        }

        Set<String> uniqueLicenses = new HashSet<>();
        long nonCompliantCount = 0;

        for (LicenseEntry entry : inventory) {
            breakdown.put(entry.riskCategory(), breakdown.getOrDefault(entry.riskCategory(), 0L) + 1);
            if (entry.license() != null && !entry.license().isBlank()) {
                uniqueLicenses.add(entry.license());
            }
            if (!entry.compliant()) {
                nonCompliantCount++;
            }
        }

        return new LicenseSummary(
                inventory.size(),
                uniqueLicenses.size(),
                nonCompliantCount,
                breakdown);
    }

    private String extractLicenseFromSbom(JsonNode artifact) {
        JsonNode licenses = artifact.path("licenses");
        if (licenses.isArray() && !licenses.isEmpty()) {
            List<String> values = new ArrayList<>();
            for (JsonNode lic : licenses) {
                if (lic.isTextual()) {
                    values.add(lic.asText());
                } else if (lic.isObject()) {
                    if (lic.hasNonNull("spdxExpression")) {
                        values.add(lic.path("spdxExpression").asText());
                    } else if (lic.hasNonNull("value")) {
                        values.add(lic.path("value").asText());
                    } else if (lic.has("license") && lic.path("license").hasNonNull("id")) {
                        values.add(lic.path("license").path("id").asText());
                    } else if (lic.has("license") && lic.path("license").hasNonNull("name")) {
                        values.add(lic.path("license").path("name").asText());
                    }
                }
            }
            if (!values.isEmpty()) {
                return String.join(" OR ", values);
            }
        }
        return null;
    }

    /**
     * What an undeclared licence is recorded as: unknown, and nothing more.
     *
     * <p><b>It used to be guessed from the package name</b> — "spring" meant Apache-2.0, "react"
     * meant MIT, a name containing "gpl" meant GPL-2.0 — and <b>anything unrecognised was declared
     * MIT</b>, which is permissive, so compliant under every policy. The inventory, the scorecard
     * grade and the conflict evaluation therefore reported as cleared exactly the components whose
     * licence nobody had read, to an auditor with no way of telling a declared licence from an
     * invented one. Unknown is what the risk classification and the conflict matrix already have a
     * category for; a policy that refuses unknown licences can now actually see them.
     */
    private static final String UNDECLARED = "UNKNOWN";

    private LicensePolicy toDomainPolicy(LicensePolicyEntity entity) {
        Set<LicenseRiskCategory> disallowed = new HashSet<>();
        if (entity.getDisallowedCategories() != null) {
            for (String part : entity.getDisallowedCategories().split(",")) {
                try {
                    disallowed.add(LicenseRiskCategory.valueOf(part.trim()));
                } catch (IllegalArgumentException misspelt) {
                    // A misspelt category was dropped in silence, and the category it meant to
                    // forbid was then allowed. Still dropped — failing every read over it would
                    // take the screen down — but said.
                    if (!part.isBlank()) {
                        log.warn("Licence policy names an unknown risk category \"{}\" — it forbids nothing.", part.trim());
                    }
                }
            }
        }
        Set<String> allowed = entity.getAllowedLicenses() != null && !entity.getAllowedLicenses().isBlank()
                ? Arrays.stream(entity.getAllowedLicenses().split(",")).map(String::trim).collect(Collectors.toSet())
                : Set.of();
        Set<String> dis = entity.getDisallowedLicenses() != null && !entity.getDisallowedLicenses().isBlank()
                ? Arrays.stream(entity.getDisallowedLicenses().split(",")).map(String::trim).collect(Collectors.toSet())
                : Set.of();

        return new LicensePolicy(disallowed, allowed, dis);
    }

    /**
     * The licence conflicts of a named target, or of the estate for a reader who sees all of it —
     * refused otherwise, on the summary's terms.
     *
     * @throws NotFoundException for a restricted reader naming no target
     */
    @Transactional(readOnly = true)
    public List<LicenseConflictMatrix.LicenseConflict> evaluateConflicts(
            Visibility allowed, Long repoId, Long containerId, boolean isProprietaryTarget) {
        requireEstateOrTarget(allowed, repoId, containerId);
        List<LicenseEntry> inventory = getInventory(allowed, repoId, containerId);
        List<LicenseConflictMatrix.LicenseConflict> conflicts = new ArrayList<>();

        for (LicenseEntry entry : inventory) {
            LicenseConflictMatrix.LicenseConflict eval = LicenseConflictMatrix.evaluate(
                    entry.packageName(),
                    entry.packageVersion(),
                    entry.license(),
                    entry.targetKind(),
                    entry.targetName(),
                    isProprietaryTarget);

            if (eval.compatibility() != LicenseConflictMatrix.Compatibility.COMPATIBLE) {
                conflicts.add(eval);
            }
        }
        return conflicts;
    }

    public List<LicenseConflictMatrix.CompatibilityCell> getCompatibilityRules() {
        return LicenseConflictMatrix.getStandardCompatibilityRules();
    }
}
