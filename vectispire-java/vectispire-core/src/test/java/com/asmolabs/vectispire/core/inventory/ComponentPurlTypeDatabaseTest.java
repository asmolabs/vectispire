package com.asmolabs.vectispire.core.inventory;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * {@code purl_type}, the package-URL type the database derives from each component's purl (V96).
 *
 * <p>Rule coverage used to read the purls and cut each at its first slash ({@code RuleCoverage}); it now
 * reads this column, through an index, because reading the purls made every gate verdict, dashboard and
 * security overview read the whole inventory (1.0.0-rc.1 load test). That is the same answer only while the
 * column is exactly that cut — so this pins the expression, on the engine, through every way a purl is
 * written: an insert, a purl without a slash, none at all, and the build-SBOM completion's update in place.
 */
@DisplayName("a component's package-URL type")
class ComponentPurlTypeDatabaseTest extends VectispireContextTest {

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private InventoryQueryService inventory;

    @Test
    @DisplayName("is the purl up to its first slash, empty without one, null without a purl, and follows an update")
    void isThePurlsPrefix() {
        long repo = repository();
        long scan = scan(repo);

        long scoped = component(scan, repo, "pkg:npm/%40scope/left-pad@1.0.0");
        long maven = component(scan, repo, "pkg:maven/org.acme/thing@1.2");
        long slashless = component(scan, repo, "pkg:generic-thing");
        long none = component(scan, repo, null);

        assertThat(typeOf(scoped)).isEqualTo("pkg:npm/");
        assertThat(typeOf(maven)).isEqualTo("pkg:maven/");
        assertThat(typeOf(slashless)).isEmpty();
        assertThat(typeOf(none)).isNull();

        // What the build-SBOM completion does to a row it reconciles: its purl rewritten in place.
        jdbc.update("update t_component set purl = ? where id = ?", "pkg:pypi/requests@2.31.0", slashless);
        assertThat(typeOf(slashless)).isEqualTo("pkg:pypi/");

        assertThat(components.distinctPurlTypesOfRepository(repo))
                .containsExactlyInAnyOrder("pkg:npm/", "pkg:maven/", "pkg:pypi/");
        assertThat(inventory.distinctPurlTypesOf(new ScanTarget.Repository(repo)))
                .containsExactlyInAnyOrder("pkg:npm/", "pkg:maven/", "pkg:pypi/");
        assertThat(inventory.distinctPurlTypes()).contains("pkg:npm/", "pkg:maven/", "pkg:pypi/");
    }

    private String typeOf(long component) {
        return jdbc.queryForObject("select purl_type from t_component where id = ?", String.class, component);
    }

    private long component(long scan, long repo, String purl) {
        jdbc.update("insert into t_component (scan_id, name, version, purl, repo_id) values (?, ?, ?, ?, ?)",
                scan, "c", "1", purl, repo);
        return jdbc.queryForObject("select max(id) from t_component", Long.class);
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/purl-type.git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long scan(long repo) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repo);
        scan.setStatus("completed");
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now());
        return scans.save(scan).getId();
    }
}
