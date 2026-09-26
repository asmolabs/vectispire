package com.asmolabs.vectispire.core.services.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.targets.ContainerView;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.Containers;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Queueing a scan on request, against the database.
 *
 * <p>The class every manual scan goes through, and it had no test of its own: the routes exercised
 * the happy path. What is pinned here is what the scheduler and the two routes rely on it for —
 * the target's requirement copied at queue time, and a second request refused rather than stacked.
 */
@DisplayName("queueing a scan on request")
class ScanTriggerDatabaseTest extends VectispireContextTest {

    @Autowired
    private ScanTriggerService trigger;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Containers containers;

    @Autowired
    private Scans scans;

    @Test
    @DisplayName("a repository scan is queued with its branch, sub-path and agent requirement")
    void queuesARepositoryScan() {
        RepositoryEntity repository = repository("production");

        ScanEntity queued = trigger.trigger(RepositoryView.of(repository));

        ScanEntity stored = scans.findById(queued.getId()).orElseThrow();
        assertThat(stored.getStatus()).isEqualTo(ScanStatus.PENDING.wireName());
        assertThat(stored.getRepoId()).isEqualTo(repository.getId());
        assertThat(stored.getBranch()).isEqualTo("release");
        assertThat(stored.getSubPath()).isEqualTo("services/api");
        assertThat(stored.getRequiredAgentLabel()).isEqualTo("production");
        assertThat(stored.getCreatedAt()).isNotNull();
    }

    @Test
    @DisplayName("the requirement is the one that held when the scan was asked for")
    void theRequirementIsCopiedAtQueueTime() {
        // Copied, not referenced: relabelling a target must not move a scan already waiting to a
        // different set of agents.
        RepositoryEntity repository = repository("production");
        ScanEntity queued = trigger.trigger(RepositoryView.of(repository));

        repository.setRequiredAgentLabel("staging");
        repositories.save(repository);

        assertThat(scans.findById(queued.getId()).orElseThrow().getRequiredAgentLabel()).isEqualTo("production");
    }

    @Test
    @DisplayName("a second request while one is waiting is refused, and writes nothing")
    void aSecondRequestIsRefused() {
        RepositoryEntity repository = repository(null);
        trigger.trigger(RepositoryView.of(repository));

        assertThatThrownBy(() -> trigger.trigger(RepositoryView.of(repository)))
                .isInstanceOf(ScanTriggerService.AlreadyQueuedException.class);
        assertThat(scans.countByStatus(ScanStatus.PENDING.wireName())).isEqualTo(1);
    }

    @Test
    @DisplayName("once the waiting scan is claimed, a new one may be queued")
    void aClaimedScanNoLongerBlocks() {
        // Only a *waiting* scan refuses: blocking on a running one would make a long scan prevent
        // the next request until it finished.
        RepositoryEntity repository = repository(null);
        ScanEntity first = trigger.trigger(RepositoryView.of(repository));
        first.setStatus(ScanStatus.SCANNING.wireName());
        scans.save(first);

        assertThat(trigger.trigger(RepositoryView.of(repository)).getId()).isNotEqualTo(first.getId());
    }

    @Test
    @DisplayName("a container scan carries the branch the scheduler writes, so the two are indistinguishable")
    void queuesAContainerScan() {
        ContainerEntity container = new ContainerEntity();
        container.setImageName("registry.example.invalid/shop");
        container.setTag("1.4.2");
        container.setRequiredAgentLabel("dmz");
        container = containers.save(container);

        ScanEntity stored = scans.findById(trigger.trigger(ContainerView.of(container)).getId()).orElseThrow();

        assertThat(stored.getContainerId()).isEqualTo(container.getId());
        assertThat(stored.getRepoId()).isNull();
        assertThat(stored.getBranch()).isEqualTo("n/a");
        assertThat(stored.getRequiredAgentLabel()).isEqualTo("dmz");
        assertThatThrownBy(() -> trigger.trigger(ContainerView.of(containers.findById(stored.getContainerId()).orElseThrow())))
                .isInstanceOf(ScanTriggerService.AlreadyQueuedException.class);
    }

    private RepositoryEntity repository(String label) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/shop.git");
        repository.setBranch("release");
        repository.setSubPath("services/api");
        repository.setRequiredAgentLabel(label);
        return repositories.save(repository);
    }
}
