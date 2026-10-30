package com.asmolabs.vectispire.core.inventory;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.licenses.LicenseConflictMatrix;
import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.licenses.LicensePolicy;
import com.asmolabs.vectispire.common.domain.licenses.LicenseRiskCategory;
import com.asmolabs.vectispire.common.domain.sbom.BuildSbom;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.inventory.persistence.LicensePolicyRepository;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.targets.TargetDeletionService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The estate's licence inventory and its conflicts served from memory, against the read they replaced
 * ({@code LicenseGovernanceService.readInventory}): the same entries, field by field, <b>in the same
 * order</b> — the unpaged answer has always been a hash map's iteration, and a client written against
 * 0.11.0 sees no byte move — for an administrator, for restricted readers, and for a reader granted
 * nothing, cold, warm, and after each event that moves an inventory.
 *
 * <p>The estate is large enough that its keys share buckets, holds a history (two scans of one target
 * declaring a component under different licences), a scan naming a repository and an image, scans of no
 * target, a purged SBOM, and a build SBOM completing a scan — the one read that takes a key out of the
 * map before putting another, so the one that proves the order is rebuilt rather than approximated.
 *
 * <p>A second service, built over the same database, plays a second control-plane instance: it keeps
 * its own entries and must see every event the first one causes, through the census both read.
 */
@DisplayName("the licence inventory served from memory answers what the database read answered")
class LicenceInventoryInMemoryDatabaseTest extends VectispireContextTest {

    private static final List<String> LICENCES = List.of(
            "MIT", "Apache-2.0", "GPL-3.0-only", "AGPL-3.0-only", "LGPL-2.1-only", "", "BSD-3-Clause", "MPL-2.0");

    @Autowired
    private LicenseGovernanceService licences;

    @Autowired
    private LicensePolicyRepository policies;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private ScanCatalog scanCatalog;

    @Autowired
    private TargetCatalog targetCatalog;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AuditLogService audit;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private Clock clock;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private BuildSbomInventory builds;

    @Autowired
    private TargetDeletionService deletion;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("equal entry for entry and in order, for every reader, before and after every event that moves an inventory")
    void answersAlike() {
        List<ScanTarget.Repository> repos = new ArrayList<>();
        for (int index = 0; index < 12; index++) {
            ScanTarget.Repository repository = repository("memory-r" + index);
            repos.add(repository);
            // Two scans of overlapping components, the newer declaring some under another licence.
            long older = scan(repository, null, sbom(index, 0, 30));
            long newer = scan(repository, null, sbom(index, 1, 34));
            components(older, index, 30, 6);
            components(newer, index, 34, 6);
            licenceFinding(older, "found-" + index, "1." + index, LICENCES.get(index % LICENCES.size()));
        }
        List<ScanTarget.Container> images = new ArrayList<>();
        for (int index = 0; index < 4; index++) {
            ScanTarget.Container image = container("memory-c" + index);
            images.add(image);
            long scan = scan(null, image, sbom(100 + index, 0, 25));
            components(scan, 100 + index, 25, 3);
        }
        // A scan naming a repository and an image: the repository's, whichever target it is read for.
        long both = scan(repos.get(3), images.get(0), sbom(200, 0, 12));
        components(both, 200, 12, 2);
        // Scans attached to no target: the administrator's alone.
        long none = scan(null, null, sbom(300, 0, 15));
        components(none, 300, 15, 2);
        scan(null, null, sbom(300, 1, 10));
        // An SBOM the retention purge dropped, its components speaking for it.
        long purged = scan(repos.get(5), null, sbom(500, 0, 10));
        components(purged, 500, 10, 0);
        scans.dropPayloads(List.of(purged));
        // A scan whose SBOM lists a component at an unknown version, which a build SBOM completes below.
        ScanTarget.Repository built = repos.get(7);
        long completedLater = scan(built, null, sbomWithUnknownParent());
        componentWithPurl(completedLater, "parent", "UNKNOWN", "pkg:maven/org.example/parent@UNKNOWN");

        List<Visibility> readers = List.of(
                Visibility.everything(),
                Visibility.only(List.of(repos.get(0), repos.get(1), repos.get(7), images.get(0))),
                // Their image, not the repository whose scan also names it.
                Visibility.only(List.of(images.get(0), images.get(2))),
                Visibility.only(List.of()));

        LicenseGovernanceService secondInstance = new LicenseGovernanceService(
                policies, components, scanCatalog, targetCatalog, objectMapper, audit, transactions, clock);

        // Cold for the restricted readers first, then for the administrator, then warm for each.
        assertAlike(readers, licences);
        assertAlike(readers, licences);
        assertAlike(readers, secondInstance);

        // The oracle is not trivial where it matters: keys of no target, a history, a pair sharing a bucket.
        List<LicenseEntry> estate = licences.readInventory(Visibility.everything());
        assertThat(estate).filteredOn(entry -> "general".equals(entry.targetKind())).isNotEmpty();
        assertThat(estate).filteredOn(entry -> !entry.compliant()).isNotEmpty();
        assertThat(estate).as("an order a sort would not give").isNotEqualTo(estate.stream()
                .sorted(Comparator.comparing(LicenseEntry::targetKind)
                        .thenComparing(LicenseEntry::targetId, Comparator.nullsFirst(Comparator.naturalOrder()))
                        .thenComparing(LicenseEntry::packageName))
                .toList());

        long[] unindexed = new long[1];
        // Each event, caused through the first instance or behind both; each instance must follow it.
        List<Runnable> events = List.of(
                // A new scan of one target.
                () -> {
                    long scan = scan(repos.get(1), null, sbom(1, 2, 40));
                    components(scan, 1, 40, 8);
                },
                // A build SBOM completes the newest scan of a repository: its row replaces the SBOM's entry.
                () -> buildSbom(built.id(), List.of(
                        new BuildSbom.Component("parent", "3.2", "pkg:maven/org.example/parent@3.2", "library", "GPL-3.0-only"),
                        new BuildSbom.Component("transitive", "1.0", "pkg:maven/org.example/transitive@1.0", "library", null))),
                // The policy, judged at each read.
                () -> licences.updatePolicy(new LicensePolicy(
                        Set.of(LicenseRiskCategory.STRONG_COPYLEFT, LicenseRiskCategory.UNKNOWN), Set.of("GPL-3.0-only"), Set.of("MIT"))),
                // A repository renamed: an entry carries its target's name of the moment.
                () -> rename(repos.get(0), "corp/memory-renamed"),
                // The retention purge drops a scan's SBOM.
                () -> scans.dropPayloads(List.of(scan(repos.get(2), null, sbom(2, 3, 5)))),
                // A scan holding an SBOM and no component row, then the backfill giving it some.
                () -> unindexed[0] = scan(repos.get(9), null, sbom(9, 4, 8)),
                () -> components(unindexed[0], 9, 12, 4),
                // A deleted target leaves.
                () -> deletion.deleteRepository(repos.get(1).id()),
                () -> deletion.deleteContainer(images.get(2).id()));
        for (Runnable event : events) {
            event.run();
            assertAlike(readers, licences);
            assertAlike(readers, secondInstance);
        }
        assertThat(licences.readInventory(Visibility.everything()))
                .filteredOn(entry -> "parent".equals(entry.packageName()))
                .singleElement().extracting(LicenseEntry::packageVersion).isEqualTo("3.2");
    }

    private void assertAlike(List<Visibility> readers, LicenseGovernanceService service) {
        for (Visibility reader : readers) {
            List<LicenseEntry> read = licences.readInventory(reader);
            assertThat(service.getInventory(reader, null, null)).as("the inventory of %s", reader)
                    .containsExactlyElementsOf(read);
            // A page is cut from the answer sorted: the same entries make the same pages.
            List<LicenseEntry> pages = new ArrayList<>();
            for (int offset = 0; ; offset += 100) {
                List<LicenseEntry> page = service.getInventory(reader, null, null, 100, offset);
                pages.addAll(page);
                if (page.size() < 100) {
                    break;
                }
            }
            assertThat(pages).as("the pages of %s", reader).containsExactlyInAnyOrderElementsOf(read);
            if (reader instanceof Visibility.Everything) {
                for (boolean proprietary : List.of(true, false)) {
                    assertThat(service.evaluateConflicts(reader, null, null, proprietary))
                            .as("the conflicts, proprietary %s", proprietary)
                            .containsExactlyElementsOf(conflictsOf(read, proprietary));
                }
            }
        }
    }

    /** The conflicts of an inventory, as the service has always evaluated them, in its order. */
    private static List<LicenseConflictMatrix.LicenseConflict> conflictsOf(List<LicenseEntry> inventory, boolean proprietary) {
        return inventory.stream()
                .map(entry -> LicenseConflictMatrix.evaluate(entry.packageName(), entry.packageVersion(), entry.license(),
                        entry.targetKind(), entry.targetName(), proprietary))
                .filter(conflict -> conflict.compatibility() != LicenseConflictMatrix.Compatibility.COMPATIBLE)
                .toList();
    }

    private void buildSbom(long repoId, List<BuildSbom.Component> listed) {
        BuildSbom sbom = new BuildSbom("1.6", Optional.empty(), listed);
        transactions.executeWithoutResult(status -> builds.record(new BuildSbomInventory.Accepted(1L, "memory-ci", repoId,
                null, null, "0".repeat(64), Instant.now(), "pipeline", UUID.randomUUID()), sbom));
    }

    private void rename(ScanTarget.Repository target, String name) {
        RepositoryEntity entity = repositories.findById(target.id()).orElseThrow();
        entity.setName(name);
        repositories.save(entity);
    }

    private ScanTarget.Repository repository(String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setName("corp/" + name);
        entity.setUrl("https://example.invalid/corp/" + name + ".git");
        entity.setBranch("main");
        return new ScanTarget.Repository(repositories.save(entity).getId());
    }

    private ScanTarget.Container container(String name) {
        ContainerEntity entity = new ContainerEntity();
        entity.setImageName("registry.example.invalid/" + name);
        entity.setTag("1.0");
        return new ScanTarget.Container(containers.save(entity).getId());
    }

    private long scan(ScanTarget.Repository repository, ScanTarget.Container container, String sbom) {
        ScanEntity entity = new ScanEntity();
        entity.setRepoId(repository == null ? null : repository.id());
        entity.setContainerId(container == null ? null : container.id());
        entity.setBranch("main");
        entity.setStatus("completed");
        entity.setCreatedAt(Instant.now());
        entity.setSbom(sbom);
        return scans.save(entity).getId();
    }

    /**
     * A Syft document of {@code count} artifacts of family {@code family}; {@code generation} shifts the
     * licences, so that two scans of one target disagree about some, and one artifact in seven has no
     * version.
     */
    private static String sbom(int family, int generation, int count) {
        StringBuilder json = new StringBuilder("{\"artifacts\":[");
        for (int index = 0; index < count; index++) {
            String licence = LICENCES.get((index + family + generation * 3) % LICENCES.size());
            json.append(index == 0 ? "" : ",").append("{\"name\":\"lib").append(family).append('-').append(index).append('"');
            if (index % 7 != 3) {
                json.append(",\"version\":\"").append(index % 5).append('.').append(family).append('"');
            }
            json.append(",\"purl\":\"pkg:npm/lib").append(family).append('-').append(index).append('"');
            if (!licence.isEmpty()) {
                json.append(",\"licenses\":[{\"value\":\"").append(licence).append("\"}]");
            }
            json.append('}');
        }
        return json.append("]}").toString();
    }

    private static String sbomWithUnknownParent() {
        return "{\"artifacts\":[{\"name\":\"parent\",\"version\":\"UNKNOWN\",\"purl\":\"pkg:maven/org.example/parent@UNKNOWN\","
                + "\"licenses\":[{\"value\":\"Apache-2.0\"}]},{\"name\":\"sibling\",\"version\":\"1.0\"}]}";
    }

    /**
     * The component rows of a scan of family {@code family}: its first {@code listed} artifacts, as the SBOM
     * states them, and {@code extra} only the rows name.
     */
    private void components(long scanId, int family, int listed, int extra) {
        Map<String, Object> scan = jdbc.queryForMap("select repo_id, container_id from t_scan where id = ?", scanId);
        List<Object[]> rows = new ArrayList<>();
        for (int index = 0; index < listed + extra; index++) {
            String name = index < listed ? "lib" + family + "-" + index : "row" + family + "-" + index;
            String version = index % 7 == 3 ? null : (index % 5) + "." + family;
            rows.add(new Object[] {scanId, scan.get("repo_id"), scan.get("container_id"), Timestamp.from(Instant.now()),
                name, version, "pkg:npm/" + name + "?row=" + scanId});
        }
        jdbc.batchUpdate("insert into t_component (scan_id, repo_id, container_id, scan_created_at, name, version, purl, type)"
                + " values (?, ?, ?, ?, ?, ?, ?, 'library')", rows);
    }

    private void componentWithPurl(long scanId, String name, String version, String purl) {
        Map<String, Object> scan = jdbc.queryForMap("select repo_id, container_id from t_scan where id = ?", scanId);
        jdbc.update("insert into t_component (scan_id, repo_id, container_id, scan_created_at, name, version, purl, type)"
                        + " values (?, ?, ?, ?, ?, ?, ?, 'library')",
                scanId, scan.get("repo_id"), scan.get("container_id"), Timestamp.from(Instant.now()), name, version, purl);
    }

    private void licenceFinding(long scanId, String name, String version, String licence) {
        jdbc.update("insert into t_finding (scan_id, type, source, package_name, package_version, identifier, is_kev,"
                        + " created_at, reachability) values (?, 'license', 'trivy', ?, ?, ?, false, ?, 'UNKNOWN')",
                scanId, name, version, licence, Timestamp.from(Instant.now()));
    }
}
