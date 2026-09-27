package com.asmolabs.vectispire.core.agents;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.agents.AgentKind;
import com.asmolabs.vectispire.common.domain.agents.CredentialsMode;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.AgentKeys;
import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanDispatcher;
import com.asmolabs.vectispire.core.scanning.WorkerProperties;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The labels nobody serves, with the built-in worker counted the way the queue counts it.
 *
 * <p>On real rows, like {@code CredentialedBacklogTest}: the figure is the enabled agents and the
 * waiting scans agreeing, and the worker is the one executor that is not a row.
 */
@DisplayName("the labels nobody serves, and the built-in worker")
class UnroutableWorkerTest extends VectispireContextTest {

    @Autowired
    private AgentRepository agents;

    @Autowired
    private AgentKeys keys;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanCatalog scanCatalog;

    @Autowired
    private TargetCatalog targetCatalog;

    @Autowired
    private AuditLogService audit;

    @Autowired
    private TransactionTemplate transactions;

    /** The context's own: the apitest profile gives this control plane no runner. */
    @Autowired
    private ScanDispatcher withoutRunner;

    private ScanDispatcher withRunner;

    @BeforeEach
    void queue() {
        withRunner = mock(ScanDispatcher.class);
        when(withRunner.runsScansHere()).thenReturn(true);

        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/dmz.git");
        repository.setName("dmz");
        repository.setBranch("main");
        long repoId = repositories.save(repository).getId();

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.PENDING.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setAttempts(0);
        scan.setRequiredAgentLabel("dmz");
        scans.save(scan);
    }

    private List<AgentAdministrationService.Unroutable> unroutable(boolean enabled, ScanDispatcher dispatcher) {
        return new AgentAdministrationService(agents, keys, scanCatalog, targetCatalog, audit,
                        new BuiltInWorker(new WorkerProperties(enabled, 2, "dmz"), dispatcher), transactions,
                        Clock.systemUTC())
                .unroutable();
    }

    @Test
    @DisplayName("switched off, the worker's labels are served by nobody")
    void aDisabledWorkerServesNothing() {
        assertThat(unroutable(false, withRunner))
                .containsExactly(new AgentAdministrationService.Unroutable("dmz", 1));
    }

    @Test
    @DisplayName("switched on without a runner, it claims nothing, so it serves nothing either")
    void aWorkerWithoutARunnerServesNothing() {
        assertThat(unroutable(true, withoutRunner))
                .containsExactly(new AgentAdministrationService.Unroutable("dmz", 1));
    }

    @Test
    @DisplayName("running, it serves its labels; so does an enabled agent carrying one")
    void aRunningWorkerOrAnAgentServes() {
        assertThat(unroutable(true, withRunner)).isEmpty();

        AgentEntity agent = new AgentEntity();
        agent.setName("dmz-agent");
        agent.setKind(AgentKind.REMOTE.wireName());
        agent.setCredentialsMode(CredentialsMode.LOCAL.wireName());
        agent.setLabels("dmz");
        agent.setEnabled(true);
        agent.setCreatedAt(Instant.now());
        agents.save(agent);
        assertThat(unroutable(false, withoutRunner)).isEmpty();
    }
}
