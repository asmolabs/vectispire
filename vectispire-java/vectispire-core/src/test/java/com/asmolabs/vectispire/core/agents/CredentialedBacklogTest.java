package com.asmolabs.vectispire.core.agents;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.agents.AgentKind;
import com.asmolabs.vectispire.common.domain.agents.CredentialsMode;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanDispatcher;
import com.asmolabs.vectispire.core.scanning.WorkerProperties;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyRepository;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The scans needing a credential that nobody able to be handed it can take, on real rows.
 *
 * <p>On the application's own tables rather than on mocks, because the figure is three reads
 * agreeing — the agents, the waiting scans grouped by label and repository, which repositories carry
 * a credential — and a mock of each would agree with whatever the test said.
 */
@DisplayName("the scans waiting for an executor able to be handed their credential")
class CredentialedBacklogTest extends VectispireContextTest {

    @Autowired
    private AgentRepository agents;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private SshKeyRepository sshKeys;

    @Autowired
    private ScanCatalog scanCatalog;

    @Autowired
    private TargetCatalog targetCatalog;

    @Autowired
    private ScanDispatcher dispatcher;

    @Autowired
    private MeterRegistry registry;

    private long keyed;
    private long open;

    @BeforeEach
    void targets() {
        SshKeyEntity key = new SshKeyEntity();
        key.setId(UUID.randomUUID());
        key.setName("deploy");
        key.setPrivateKey("v2:not-read-by-this-test");
        key.setCreatedAt(Instant.now());
        sshKeys.save(key);
        keyed = repository("keyed", key.getId());
        open = repository("open", null);
    }

    /** The built-in worker off, as on a control plane whose executors are all remote. */
    private CredentialedBacklog withoutWorker() {
        return new CredentialedBacklog(agents, scanCatalog, targetCatalog, new WorkerProperties(false, 2, ""), dispatcher);
    }

    @Test
    @DisplayName("a delegated agent with no verified key serves nobody's credential: its keyed scans are counted, and it is named")
    void anUnverifiedAgentIsNoExecutor() {
        agent("edge", CredentialsMode.DELEGATED, "", false, true);
        pending(keyed, null);
        pending(keyed, null);
        pending(open, null);
        pendingImage();

        CredentialedBacklog.Unserved unserved = withoutWorker().unserved();

        // The two keyed scans: the open repository's and the image's go to the agent as they are.
        assertThat(unserved).isEqualTo(new CredentialedBacklog.Unserved(2, List.of(""), List.of("edge")));
        // The application's own gauge reads the same figure: the apitest profile runs no worker.
        assertThat(registry.get("vectispire.scans.credential.unserved").gauge().value()).isEqualTo(2.0);
    }

    @Test
    @DisplayName("a local agent, a delegated one with a verified key, or the built-in worker takes them")
    void aCapableExecutorTakesThem() {
        agent("edge", CredentialsMode.DELEGATED, "", false, true);
        pending(keyed, null);
        assertThat(withoutWorker().unserved().scans()).isEqualTo(1);

        // Disabled, it serves nobody.
        UUID local = agent("local", CredentialsMode.LOCAL, "", false, false);
        assertThat(withoutWorker().unserved().scans()).isEqualTo(1);
        AgentEntity row = agents.findById(local).orElseThrow();
        row.setEnabled(true);
        agents.save(row);
        assertThat(withoutWorker().unserved()).isEqualTo(CredentialedBacklog.Unserved.NONE);
        agents.deleteById(local);

        agent("sealed", CredentialsMode.DELEGATED, "", true, true);
        assertThat(withoutWorker().unserved()).isEqualTo(CredentialedBacklog.Unserved.NONE);
    }

    @Test
    @DisplayName("the built-in worker counts only when it runs: switched on and with a runner")
    void theWorkerCountsWhenItRuns() {
        pending(keyed, null);
        ScanDispatcher running = mock(ScanDispatcher.class);
        when(running.runsScansHere()).thenReturn(true);

        assertThat(new CredentialedBacklog(agents, scanCatalog, targetCatalog, new WorkerProperties(true, 2, ""), running)
                        .unserved())
                .isEqualTo(CredentialedBacklog.Unserved.NONE);
        // Switched on, but no runner: it claims nothing (ScanDispatcher.dispatch), so it serves nothing.
        assertThat(new CredentialedBacklog(agents, scanCatalog, targetCatalog, new WorkerProperties(true, 2, ""), dispatcher)
                        .unserved().scans())
                .isEqualTo(1);
    }

    @Test
    @DisplayName("a label only an unverified agent carries is not served by a capable one without it")
    void theLabelDecides() {
        agent("edge", CredentialsMode.DELEGATED, "dmz", false, true);
        agent("local", CredentialsMode.LOCAL, "", false, true);
        pending(keyed, "dmz");
        pending(keyed, null);

        // The unlabelled scan goes to the local agent; the dmz one waits, and the agent that carries
        // the label is the one to fix.
        assertThat(withoutWorker().unserved()).isEqualTo(new CredentialedBacklog.Unserved(1, List.of("dmz"), List.of("edge")));

        ScanDispatcher running = mock(ScanDispatcher.class);
        when(running.runsScansHere()).thenReturn(true);
        assertThat(new CredentialedBacklog(agents, scanCatalog, targetCatalog, new WorkerProperties(true, 2, "dmz"), running)
                        .unserved())
                .isEqualTo(CredentialedBacklog.Unserved.NONE);
    }

    private UUID agent(String name, CredentialsMode mode, String labels, boolean verifiedSealingKey, boolean enabled) {
        AgentEntity agent = new AgentEntity();
        agent.setName(name);
        agent.setKind(AgentKind.REMOTE.wireName());
        agent.setCredentialsMode(mode.wireName());
        agent.setLabels(labels);
        agent.setEnabled(enabled);
        agent.setCreatedAt(Instant.now());
        if (verifiedSealingKey) {
            agent.setSealingPublicKey(new SealedEnvelope().generateKeyPair().publicKey());
        }
        return agents.save(agent).getId();
    }

    private long repository(String name, UUID sshKeyId) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + ".git");
        repository.setName(name);
        repository.setBranch("main");
        repository.setSshKeyId(sshKeyId);
        return repositories.save(repository).getId();
    }

    private void pending(long repoId, String label) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.PENDING.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setAttempts(0);
        scan.setRequiredAgentLabel(label);
        scans.save(scan);
    }

    private void pendingImage() {
        ContainerEntity image = new ContainerEntity();
        image.setImageName("team/service-" + System.nanoTime());
        image.setTag("1.0");
        ScanEntity scan = new ScanEntity();
        scan.setContainerId(containers.save(image).getId());
        scan.setBranch("");
        scan.setStatus(ScanStatus.PENDING.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setAttempts(0);
        scans.save(scan);
    }
}
