package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.apis.ApiVisibility;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.ApiContracts;
import com.asmolabs.vectispire.core.repositories.ApiEndpoints;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * What a failed analyzer must not be allowed to erase.
 *
 * <p><b>Written for a defect that produced a wrong answer rather than a missing one.</b>
 * {@code ScanIngestor} flattened both {@code Optional}s with {@code orElse(List.of())}, and
 * {@code record} deleted both tables before writing back only what was non-empty. So a contract
 * cataloguer that fell over erased every contract the repository had — and
 * {@code ShadowApiDiff} reads an empty contract list as <em>nothing declared</em>, which turns
 * every endpoint into a shadow API. The attack-surface screen went red because a tool failed.
 *
 * <p>The two cases below are the pair that matters: absent leaves the half alone, empty clears it.
 * Asserted against a real database rather than a mock, because the defect was in what
 * {@code delete…} did, and a mock of a repository proves only that the mock was called.
 */
@DisplayName("the API inventory, when an analyzer did not run")
class ApiInventoryDatabaseTest extends VectispireContextTest {

    @Autowired
    private ApiInventoryService inventory;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private ApiEndpoints endpoints;

    @Autowired
    private ApiContracts contracts;

    @Test
    @DisplayName("an absent cataloguer leaves yesterday's contracts in place")
    void absentContractsAreNotAnErasure() {
        long repositoryId = repository();
        ScanEntity first = scan(repositoryId);
        inventory.record(first, Optional.of(List.of(endpoint("/api/v1/checkout"))), Optional.of(List.of(contract())));

        // Scoped to this repository rather than `findAll`: the suite shares a database, and an
        // assertion over every row would pass or fail on what a neighbouring test happened to leave.
        assertThat(contracts.findByRepositoryIdOrderByCreatedAtDesc(repositoryId)).hasSize(1);

        // The extractor ran, the cataloguer did not. Before the fix this deleted the contract and
        // wrote nothing back, and the endpoint then read as undocumented.
        ScanEntity second = scan(repositoryId);
        inventory.record(second, Optional.of(List.of(endpoint("/api/v1/checkout"))), Optional.empty());

        assertThat(contracts.findByRepositoryIdOrderByCreatedAtDesc(repositoryId))
                .as("a cataloguer that did not run must not erase what the last one found")
                .hasSize(1);
        assertThat(endpoints.findByRepositoryIdOrderByPathAsc(repositoryId)).hasSize(1);
    }

    @Test
    @DisplayName("a cataloguer that ran and found nothing does clear them")
    void emptyContractsAreAnAnswer() {
        long repositoryId = repository();
        inventory.record(scan(repositoryId), Optional.of(List.of(endpoint("/api/v1/checkout"))), Optional.of(List.of(contract())));
        assertThat(contracts.findByRepositoryIdOrderByCreatedAtDesc(repositoryId)).hasSize(1);

        // Present and empty is not the same case: the cataloguer ran, and the target declares no
        // contracts any more. Keeping the old ones would be the opposite mistake.
        inventory.record(scan(repositoryId), Optional.of(List.of(endpoint("/api/v1/checkout"))), Optional.of(List.of()));

        assertThat(contracts.findByRepositoryIdOrderByCreatedAtDesc(repositoryId)).isEmpty();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setName("ours");
        repository.setUrl("https://example.invalid/ours.git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private ScanEntity scan(long repositoryId) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(Instant.parse("2026-08-26T10:00:00Z"));
        return scans.save(scan);
    }

    private static ApiEndpoint endpoint(String path) {
        return new ApiEndpoint(
                "POST", path, true, "Bearer", ApiVisibility.PUBLIC,
                "src/Controller.java", 20, "Spring Web", "checkout", "Process checkout", "checkout");
    }

    private static ApiContract contract() {
        return new ApiContract("openapi.yaml", "openapi", "Checkout API", "1.0.0", 1, List.of("/api/v1/checkout"));
    }
}
