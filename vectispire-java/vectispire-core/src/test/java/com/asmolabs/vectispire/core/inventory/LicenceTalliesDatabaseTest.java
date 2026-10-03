package com.asmolabs.vectispire.core.inventory;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.licenses.LicensePolicy;
import com.asmolabs.vectispire.common.domain.licenses.LicenseRiskCategory;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.TargetDeletionService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The licence tallies the dashboard's ranking reads: the inventory's own count, kept per target, and
 * recounted when — and only when — what the inventory is made of moved.
 *
 * <p>Each invalidation case writes its change <b>the way the product writes it</b> — a scan's SBOM,
 * findings and status in one step, the retention purge's {@code dropPayloads}, component rows given to
 * a scan holding an SBOM — after a first read has kept a tally, and expects the next read to see it.
 * One case per line of the list in {@code LicenseGovernanceService.violationsByTarget}: a stamp that
 * forgot one of them keeps serving the tally from before.
 */
@DisplayName("the licence tallies behind the ranking")
class LicenceTalliesDatabaseTest extends VectispireContextTest {

    /** Unknown licences refused too, so that a component row with no SBOM entry weighs. */
    private static final LicensePolicy STRICT = new LicensePolicy(
            Set.of(LicenseRiskCategory.STRONG_COPYLEFT, LicenseRiskCategory.FORBIDDEN, LicenseRiskCategory.UNKNOWN),
            Set.of(),
            Set.of());

    @Autowired
    private LicenseGovernanceService licences;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private TargetDeletionService deletion;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("count what the inventory counts, for an administrator and for a restricted reader, served warm or cold")
    void agreeWithTheInventory() {
        licences.updatePolicy(STRICT);
        ScanTarget.Repository mixed = repository("mixed");
        long older = scan(mixed, null, sbom("a@1=MIT", "b@1=GPL-3.0-only"));
        long newer = scan(mixed, null, sbom("a@1=GPL-3.0-only", "c@1="));
        components(newer, "a@1", "c@1", "d@1");
        licenceFinding(older, "e", "1", "AGPL-3.0-only");

        ScanTarget.Repository purged = repository("purged");
        long dropped = scan(purged, null, sbom("p@1=GPL-3.0-only"));
        components(dropped, "p@1", "q@1");
        scans.dropPayloads(List.of(dropped));

        ScanTarget.Container image = container("image");
        scan(null, image, sbom("i@1=MIT", "j@1=GPL-2.0-only"));
        // Of the repository it names, whichever target it is read for.
        ScanTarget.Repository built = repository("built");
        scan(built, image, sbom("k@1=GPL-3.0-only"));
        // Attached to neither: no target's.
        scan(null, null, sbom("g@1=GPL-3.0-only"));

        Visibility restricted = Visibility.only(List.of(mixed, image));

        // Cold for the restricted reader first, then warm for the administrator, then served to the
        // restricted reader from what the administrator's read kept.
        assertThat(nonZero(licences.violationsByTarget(restricted))).isEqualTo(fromInventory(restricted));
        Map<ScanTarget, Long> everything = nonZero(licences.violationsByTarget(Visibility.everything()));
        assertThat(everything).isEqualTo(fromInventory(Visibility.everything()));
        assertThat(everything).containsOnlyKeys(mixed, purged, image, built);
        assertThat(licences.violationsByTarget(restricted)).containsOnlyKeys(mixed, image);
        assertThat(nonZero(licences.violationsByTarget(restricted))).isEqualTo(fromInventory(restricted));
        // a@1 is the newer scan's GPL, b, c (unknown), d (a component the SBOM does not declare), e.
        assertThat(everything.get(mixed)).isEqualTo(5);
    }

    @Test
    @DisplayName("a new scan's SBOM is counted at the next read")
    void aNewScan() {
        ScanTarget.Repository target = repository("new-scan");
        scan(target, null, sbom("a@1=MIT"));
        assertThat(licences.violationsByTarget(Visibility.everything())).containsEntry(target, 0L);

        scan(target, null, sbom("b@1=GPL-3.0-only"));

        assertThat(licences.violationsByTarget(Visibility.everything())).containsEntry(target, 1L);
    }

    @Test
    @DisplayName("a scan whose write moves its status and adds a licence finding, and no SBOM, is counted")
    void theWriteThatEndsAScan() {
        ScanTarget.Repository target = repository("status");
        scan(target, null, sbom("a@1=MIT"));
        ScanEntity running = new ScanEntity();
        running.setRepoId(target.id());
        running.setBranch("main");
        running.setStatus("scanning");
        running.setCreatedAt(Instant.now());
        running = scans.save(running);
        assertThat(licences.violationsByTarget(Visibility.everything())).containsEntry(target, 0L);

        // What the write does for a scan whose licence scanner reported and whose SBOM is absent: the
        // finding and the status, in one step; nothing is added, no SBOM appears.
        licenceFinding(running.getId(), "x", "1", "AGPL-3.0-only");
        running.setStatus("completed");
        scans.save(running);

        assertThat(licences.violationsByTarget(Visibility.everything())).containsEntry(target, 1L);
    }

    @Test
    @DisplayName("an SBOM the retention purge drops is no longer counted, its components speaking for it")
    void aDroppedSbom() {
        ScanTarget.Repository target = repository("dropped");
        long scan = scan(target, null, sbom("a@1=GPL-3.0-only"));
        components(scan, "a@1");
        // And a scan the inventory never indexed: nothing but the SBOM count says its document is gone.
        ScanTarget.Repository unindexed = repository("unindexed");
        long bare = scan(unindexed, null, sbom("a@1=GPL-3.0-only"));
        assertThat(licences.violationsByTarget(Visibility.everything()))
                .containsEntry(target, 1L)
                .containsEntry(unindexed, 1L);

        scans.dropPayloads(List.of(scan, bare));

        // Unknown now, which the default policy allows; and nothing at all for the scan with no rows.
        assertThat(licences.violationsByTarget(Visibility.everything()))
                .containsEntry(target, 0L)
                .containsEntry(unindexed, 0L);
    }

    @Test
    @DisplayName("components the backfill gives a scan holding an SBOM are counted")
    void aBackfilledScan() {
        licences.updatePolicy(STRICT);
        ScanTarget.Repository target = repository("backfilled");
        long scan = scan(target, null, sbom("a@1=MIT"));
        assertThat(licences.violationsByTarget(Visibility.everything())).containsEntry(target, 0L);

        // A row the SBOM's entries do not key alike — a version the document wrote as a number, say.
        components(scan, "a@1", "b@");

        assertThat(licences.violationsByTarget(Visibility.everything())).containsEntry(target, 1L);
    }

    @Test
    @DisplayName("a policy change is judged at the next read, without a recount")
    void aPolicyChange() {
        ScanTarget.Repository target = repository("policy");
        scan(target, null, sbom("a@1=", "b@1=MIT"));
        assertThat(licences.violationsByTarget(Visibility.everything())).containsEntry(target, 0L);

        licences.updatePolicy(STRICT);

        assertThat(licences.violationsByTarget(Visibility.everything())).containsEntry(target, 1L);
    }

    @Test
    @DisplayName("a deleted target leaves the tallies")
    void aDeletedTarget() {
        ScanTarget.Repository kept = repository("kept");
        scan(kept, null, sbom("a@1=GPL-3.0-only"));
        ScanTarget.Repository gone = repository("gone");
        scan(gone, null, sbom("a@1=GPL-3.0-only"));
        assertThat(licences.violationsByTarget(Visibility.everything())).containsKeys(kept, gone);

        deletion.deleteRepository(gone.id());

        assertThat(licences.violationsByTarget(Visibility.everything())).containsOnlyKeys(kept);
    }

    /** The count the ranking used to take: the refused entries of the inventory, by target. */
    private Map<ScanTarget, Long> fromInventory(Visibility allowed) {
        return licences.getInventory(allowed, null, null).stream()
                .filter(entry -> !entry.compliant() && entry.targetId() != null && !"general".equals(entry.targetKind()))
                .collect(Collectors.groupingBy(LicenceTalliesDatabaseTest::targetOf, Collectors.counting()));
    }

    private static ScanTarget targetOf(LicenseEntry entry) {
        return "repository".equals(entry.targetKind())
                ? new ScanTarget.Repository(entry.targetId())
                : new ScanTarget.Container(entry.targetId());
    }

    private static Map<ScanTarget, Long> nonZero(Map<ScanTarget, Long> counts) {
        Map<ScanTarget, Long> kept = new HashMap<>();
        counts.forEach((target, count) -> {
            if (count > 0) {
                kept.put(target, count);
            }
        });
        return kept;
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

    /** A Syft document of {@code name@version=licence} artifacts; an empty licence declares none. */
    private static String sbom(String... artifacts) {
        StringBuilder json = new StringBuilder("{\"artifacts\":[");
        for (int index = 0; index < artifacts.length; index++) {
            String[] nameAndLicence = artifacts[index].split("=", -1);
            String[] nameAndVersion = nameAndLicence[0].split("@", -1);
            json.append(index == 0 ? "" : ",")
                    .append("{\"name\":\"").append(nameAndVersion[0])
                    .append("\",\"version\":\"").append(nameAndVersion[1]).append('"');
            if (!nameAndLicence[1].isEmpty()) {
                json.append(",\"licenses\":[{\"value\":\"").append(nameAndLicence[1]).append("\"}]");
            }
            json.append('}');
        }
        return json.append("]}").toString();
    }

    /** Component rows for {@code name@version}; an empty version is none. */
    private void components(long scanId, String... components) {
        Map<String, Object> scan = jdbc.queryForMap("select repo_id, container_id from t_scan where id = ?", scanId);
        for (String component : components) {
            String[] nameAndVersion = component.split("@", -1);
            jdbc.update("insert into t_component (scan_id, repo_id, container_id, scan_created_at, name, version, type)"
                            + " values (?, ?, ?, ?, ?, ?, 'library')",
                    scanId, scan.get("repo_id"), scan.get("container_id"), Timestamp.from(Instant.now()),
                    nameAndVersion[0], nameAndVersion[1].isEmpty() ? null : nameAndVersion[1]);
        }
    }

    private void licenceFinding(long scanId, String name, String version, String licence) {
        jdbc.update("insert into t_finding (scan_id, type, source, package_name, package_version, identifier, is_kev,"
                        + " created_at, reachability) values (?, 'license', 'trivy', ?, ?, ?, false, ?, 'UNKNOWN')",
                scanId, name, version, licence, Timestamp.from(Instant.now()));
    }
}
