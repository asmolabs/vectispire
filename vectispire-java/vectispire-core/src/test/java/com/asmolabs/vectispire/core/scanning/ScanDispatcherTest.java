package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.agents.CredentialsMode;
import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.ScanRunner;
import com.asmolabs.vectispire.common.scanning.ScanTask;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.crypto.internal.EncryptionProperties;
import com.asmolabs.vectispire.core.scanning.internal.PlatformMetrics;
import com.asmolabs.vectispire.core.scanning.internal.ScanQueue;
import com.asmolabs.vectispire.core.scanning.internal.ScanningProperties;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.CloneCredentials;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyRepository;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * What the dispatcher is allowed to send, and to whom.
 *
 * <p>The interesting cases here are all authorization cases, and every one of them fails
 * quietly when it is wrong: the scan runs, the results arrive, and a deployment key has left
 * the control plane towards somewhere it was promised never to go.
 */
@DisplayName("handing a scan to a worker")
class ScanDispatcherTest {

    private static final UUID KEY_ID = UUID.fromString("00000000-0000-0000-0000-0000000000aa");
    private static final String PRIVATE_KEY = "test-ssh-private-key-material";
    private static final String ENCRYPTION_KEY = EncryptionKey.generate();

    private final SealedEnvelope envelopes = new SealedEnvelope();

    private ScanQueue queue;
    private GitRepositoryRepository repositories;
    private ContainerRepository containers;
    private SshKeyRepository sshKeys;
    private com.asmolabs.vectispire.core.targets.persistence.GitTokenRepository gitTokens;
    private SettingsService settings;
    private ScanRuleSets ruleSets;
    private ScanPlugins plugins;
    private ScanDispatcher dispatcher;
    private AuditLogService audit;

    @BeforeEach
    void wire() {
        queue = mock(ScanQueue.class);
        repositories = mock(GitRepositoryRepository.class);
        containers = mock(ContainerRepository.class);
        sshKeys = mock(SshKeyRepository.class);
        gitTokens = mock(com.asmolabs.vectispire.core.targets.persistence.GitTokenRepository.class);
        settings = mock(SettingsService.class);
        ruleSets = mock(ScanRuleSets.class);
        plugins = mock(ScanPlugins.class);
        audit = mock(AuditLogService.class);

        when(ruleSets.activeHash()).thenReturn(Optional.empty());
        when(settings.isEnabled(any())).thenReturn(false);
        when(repositories.findById(1L)).thenReturn(Optional.of(repository()));
        when(sshKeys.findById(KEY_ID)).thenReturn(Optional.of(sshKey()));

        PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

        dispatcher = new ScanDispatcher(
                queue,
                new TargetCatalog(repositories, containers),
                new CloneCredentials(gitTokens, sshKeys),
                mock(ScanIngestor.class),
                new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of())),
                settings,
                ruleSets,
                plugins,
                envelopes,
                new ScanningProperties(Optional.of("linux/amd64")),
                Optional.empty(),
                audit,
                mock(PlatformMetrics.class),
                new TransactionTemplate(transactions),
                com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist.parse(""));
    }

    @Test
    @DisplayName("an agent in local mode never receives a deployment key")
    void localModeGetsNoKey() {
        queueHolds(repositoryScan());

        ScanTask task = dispatcher.claimForAgent(agent(CredentialsMode.LOCAL, null)).orElseThrow().task();

        assertThat(repositoryTarget(task).privateKey()).isNull();
        // Not merely absent from the payload: never read, so it is never decrypted either. This
        // is the defect the NestJS dispatcher had — it consulted the transport and not the mode.
        verify(sshKeys, never()).findById(any());
    }

    @Test
    @DisplayName("a delegated agent that announced a sealing key gets an envelope only it can open")
    void delegatedWithSealingKeyGetsAnEnvelope() {
        queueHolds(repositoryScan());
        SealedEnvelope.KeyPair recipient = envelopes.generateKeyPair();

        ScanTask task = dispatcher
                .claimForAgent(agent(CredentialsMode.DELEGATED, recipient.publicKey()))
                .orElseThrow()
                .task();

        String delivered = repositoryTarget(task).privateKey();
        assertThat(SealedEnvelope.isSealed(delivered)).isTrue();
        assertThat(envelopes.open(recipient, delivered)).contains(PRIVATE_KEY);
    }

    /**
     * The decision 0031 turned around. This test used to assert the opposite — that a delegated
     * agent with no sealing key received the key in the clear over an encrypted link. A link that a
     * proxy terminates is encrypted up to the proxy, and from here an agent whose announcement was
     * removed on the way looks exactly like an agent that never made one.
     *
     * <p>And since, not even claimed: each claim counted one of the scan's attempts, and a few polls
     * of such an agent spent the retries of a scan that nothing had tried.
     */
    @Test
    @DisplayName("a delegated agent with no verified sealing key is handed nothing, and the scan is not even claimed")
    void withoutAVerifiedKeyNothingLeaves() {
        queueWaitsForRepositoryOne();

        assertThatThrownBy(() -> dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null)))
                .isInstanceOf(CredentialWithheldException.class)
                .hasMessageContaining("no signing key is pinned");

        // Left out of the selection: the queue was asked for nothing of repository 1, so nothing
        // was taken, no attempt counted, and there is nothing to put back.
        verify(queue).claimWithin(any(), anyInt(), any(), argThat(keepsRepositoryOne()));
        verify(queue, never()).requeue(anyLong(), anyString());
        verify(queue, never()).requeueRefunded(anyLong(), anyString());
        verify(sshKeys, never()).findById(any());
        verify(audit, never()).record(any());
    }

    @Test
    @DisplayName("a pinned agent that has proved no sealing key is told to announce one, not to pin")
    void pinnedButNotProvedIsWithheldToo() {
        queueWaitsForRepositoryOne();
        AgentEntity row = agentRow(CredentialsMode.DELEGATED, null);
        row.setSigningPublicKey(com.asmolabs.vectispire.common.domain.crypto.ResultAttestation.generate().publicKey());

        assertThatThrownBy(() -> dispatcher.claimForAgent(com.asmolabs.vectispire.core.agents.internal.AgentViews.of(row)))
                .isInstanceOf(CredentialWithheldException.class)
                .hasMessageContaining("announced none that verified");
        verify(queue, never()).requeueRefunded(anyLong(), anyString());
    }

    @Test
    @DisplayName("an agent kept from the scans that need a key still takes an image scan behind them")
    void keptFromKeyedScansButNotFromTheRest() {
        queueWaitsForRepositoryOne();
        when(containers.findById(4L)).thenReturn(Optional.of(container()));
        org.mockito.Mockito.doReturn(new ScanQueue.AgentClaim(Optional.of(imageScan()), true))
                .when(queue).claimWithin(any(), anyInt(), any(), argThat(keepsRepositoryOne()));

        ScanTask task = dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null)).orElseThrow().task();

        assertThat(task.target()).isInstanceOf(ScanTask.Target.Image.class);
    }

    @Test
    @DisplayName("a full agent kept from a scan is answered 'nothing', not told about a key")
    void aFullAgentIsNotToldAboutAKey() {
        queueWaitsForRepositoryOne();
        when(queue.countHeld(anyString())).thenReturn(1L);

        assertThat(dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null))).isEmpty();
    }

    @Test
    @DisplayName("an agent that can take every scan has nothing left out, and its poll asks nothing more")
    void aCapableAgentExcludesNothing() {
        queueWaitsForRepositoryOne();
        SealedEnvelope.KeyPair recipient = envelopes.generateKeyPair();

        assertThat(dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, recipient.publicKey()))).isPresent();
        assertThat(dispatcher.claimForAgent(agent(CredentialsMode.LOCAL, null))).isPresent();

        verify(queue, org.mockito.Mockito.times(2)).claimWithin(any(), anyInt(), any(), eq(ScanQueue.Exclusion.NONE));
        verify(repositories, never()).findAllById(any());
    }

    /**
     * The race the selection cannot close: the repository had no key when the agent's selection read
     * it, and has one by the time the task is built. Put back, and refunded — nothing was tried, and
     * the next selection reads the key and leaves the repository out, so the refund is paid once.
     */
    @Test
    @DisplayName("a key added between the selection and the delivery: put back with its attempt refunded")
    void aKeyAddedSinceTheSelectionIsRefunded() {
        RepositoryEntity keyless = repository();
        keyless.setSshKeyId(null);
        when(repositories.findAllById(any())).thenReturn(List.of(keyless));
        queueHolds(repositoryScan());

        assertThatThrownBy(() -> dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null)))
                .isInstanceOf(CredentialWithheldException.class);

        // The selection read no key on repository 1, so it kept the agent from nothing.
        verify(queue).claimWithin(any(), anyInt(), any(),
                argThat(exclusion -> !exclusion.excludesNothing() && exclusion.among(Set.of(1L)).isEmpty()));
        verify(queue).requeueRefunded(eq(7L), anyString());
        verify(queue, never()).requeue(anyLong(), anyString());
        verify(audit, never()).record(any());
    }

    @Test
    @DisplayName("a row with a key and a token has both sealed, not the first alone")
    void bothCredentialsAreSealed() {
        repositoryUsesAnHttpsToken();
        RepositoryEntity both = repositories.findById(1L).orElseThrow();
        both.setSshKeyId(KEY_ID);
        queueHolds(repositoryScan());
        SealedEnvelope.KeyPair recipient = envelopes.generateKeyPair();

        ScanTask.Target.Repository target = repositoryTarget(
                dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, recipient.publicKey())).orElseThrow().task());

        assertThat(envelopes.open(recipient, target.privateKey())).contains(PRIVATE_KEY);
        assertThat(envelopes.open(recipient, target.https().token())).contains("glpat-secret");
    }

    @Test
    @DisplayName("an unreadable credentials mode reads as local")
    void anUnknownModeDeliversNothing() {
        queueHolds(repositoryScan());
        AgentEntity agent = agentRow(CredentialsMode.DELEGATED, null);
        agent.setCredentialsMode("something-a-later-version-wrote");

        ScanTask task = dispatcher.claimForAgent(com.asmolabs.vectispire.core.agents.internal.AgentViews.of(agent)).orElseThrow().task();

        assertThat(repositoryTarget(task).privateKey()).isNull();
    }

    @Test
    @DisplayName("an image scan carries no key whatever the agent's mode")
    void imageScansCarryNoCredentials() {
        queueHolds(imageScan());
        when(containers.findById(4L)).thenReturn(Optional.of(container()));

        ScanTask task = dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null)).orElseThrow().task();

        assertThat(task.target()).isInstanceOf(ScanTask.Target.Image.class);
        // No refusal either: with nothing to protect, the encrypted-link precaution does not
        // apply, and an image scan stays distributable to any agent.
        verify(queue, never()).requeue(anyLong(), anyString());
    }

    @Test
    @DisplayName("the SAST step is on the task only when the setting says so")
    void sastIsDecidedByTheControlPlane() {
        queueHolds(repositoryScan());
        assertThat(dispatcher.claimForAgent(agent(CredentialsMode.LOCAL, null)).orElseThrow().task().steps())
                .doesNotContain(ScanTask.Step.SAST);

        when(settings.isEnabled(Setting.SAST_ENABLED)).thenReturn(true);
        queueHolds(repositoryScan());
        assertThat(dispatcher.claimForAgent(agent(CredentialsMode.LOCAL, null)).orElseThrow().task().steps())
                .contains(ScanTask.Step.SAST);
    }

    @Test
    @DisplayName("an agent's claim is held to its limit as the queue applies it, never to the raw column")
    void anAgentClaimsWithinItsEffectiveLimit() {
        queueHolds(imageScan());
        AgentEntity agent = agentRow(CredentialsMode.LOCAL, null);

        agent.setMaxConcurrent(4);
        dispatcher.claimForAgent(com.asmolabs.vectispire.core.agents.internal.AgentViews.of(agent));
        verify(queue).claimWithin(agent.getId(), 4, List.of(), ScanQueue.Exclusion.NONE);

        // A row from before the bound: 50 is applied as 16, and nothing — null or zero — as a
        // paused agent.
        agent.setMaxConcurrent(50);
        dispatcher.claimForAgent(com.asmolabs.vectispire.core.agents.internal.AgentViews.of(agent));
        verify(queue).claimWithin(agent.getId(), 16, List.of(), ScanQueue.Exclusion.NONE);

        agent.setMaxConcurrent(0);
        dispatcher.claimForAgent(com.asmolabs.vectispire.core.agents.internal.AgentViews.of(agent));
        verify(queue).claimWithin(agent.getId(), 1, List.of(), ScanQueue.Exclusion.NONE);
    }

    @Test
    @DisplayName("a deleted SSH key fails the scan rather than cloning anonymously")
    void aMissingKeyFailsTheScan() {
        queueHolds(repositoryScan());
        when(sshKeys.findById(KEY_ID)).thenReturn(Optional.empty());

        assertThat(dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null))).isEmpty();
        verify(queue).fail(anyLong(), anyString(), anyString());
    }

    @Test
    @DisplayName("with no local runner, a dispatch round claims nothing")
    void aControlPlaneWithoutARunnerDoesNotClaim() {
        when(queue.reclaimLapsedLeases()).thenReturn(new ScanQueue.Reclaimed(List.of(), List.of()));

        assertThat(dispatcher.dispatch("worker-1", 4, List.of())).isEqualTo(new ScanDispatcher.Dispatched(0, 0, 0));

        // Claiming what it cannot run would burn one of the scan's attempts per round and fail
        // it for good in three, while a remote agent was available all along.
        verify(queue, never()).claim(anyInt(), anyString(), any());
    }

    /**
     * {@code VECTISPIRE_SCAN_MAX_CONCURRENT} was compared with every scan running anywhere, so forty
     * scans on remote agents left the built-in worker with no room at all on a machine doing nothing.
     */
    @Test
    @DisplayName("the built-in worker's room is its limit less its own scans, whatever the agents run")
    void theWorkersRoomIgnoresTheAgentsScans() {
        when(queue.reclaimLapsedLeases()).thenReturn(new ScanQueue.Reclaimed(List.of(), List.of()));
        when(queue.countRunning()).thenReturn(40L);
        when(queue.countHeld("worker-1")).thenReturn(1L);
        when(queue.claim(anyInt(), anyString(), any())).thenReturn(List.of());

        new ScanDispatcher(
                        queue, new TargetCatalog(repositories, containers), new CloneCredentials(gitTokens, sshKeys),
                        mock(ScanIngestor.class),
                        new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of())),
                        settings, ruleSets, plugins, envelopes,
                        new ScanningProperties(Optional.of("linux/amd64")),
                        Optional.of(mock(ScanRunner.class)),
                        mock(AuditLogService.class),
                        mock(PlatformMetrics.class),
                        new TransactionTemplate(mock(PlatformTransactionManager.class)),
                        com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist.parse(""))
                .dispatch("worker-1", 3, List.of());

        verify(queue).claim(2, "worker-1", List.of());
    }

    @Test
    @DisplayName("a scan whose every step failed is recorded failed, not completed")
    void aScanThatExaminedNothingIsNotCompleted() {
        ScanEntity scan = withRunner(ScanArtifacts.builder()
                .failed("dependencies", "pull access denied for temurin")
                .build(Duration.ofSeconds(2)));

        // The case this comes from: an image name that does not exist on the registry. The pull
        // fails and takes every step with it. Recorded as completed it reached the screen with a
        // green tag, and was read as "this image was scanned and is clean".
        assertThat(scan.getStatus()).isEqualTo(ScanStatus.FAILED.wireName());
        assertThat(scan.getError()).contains("pull access denied");
    }

    @Test
    @DisplayName("a result without a duration is recorded, with the duration unknown")
    void aMissingDurationIsUnknownNotACrash() {
        // It threw a NullPointerException in the write and the findings went with it.
        ScanEntity scan = withRunner(ScanArtifacts.builder().secrets(List.of()).build(null));

        assertThat(scan.getStatus()).isEqualTo(ScanStatus.COMPLETED.wireName());
        assertThat(scan.getDurationMs()).isNull();
    }

    @Test
    @DisplayName("a step that ran and found nothing keeps the scan completed")
    void aCleanScanStaysCompleted() {
        // Absent is not empty. If an empty result counted as "examined nothing", every clean
        // target would be reported as a failure — the opposite mistake, and a louder one.
        ScanEntity scan = withRunner(
                ScanArtifacts.builder().secrets(List.of()).build(Duration.ofSeconds(2)));

        assertThat(scan.getStatus()).isEqualTo(ScanStatus.COMPLETED.wireName());
    }

    @Test
    @DisplayName("a scan taken over before its turn in the round is not run")
    void aScanTakenOverBeforeItsTurnIsSkipped() {
        // A round claims several scans and runs them one after the other, all leased from the
        // claim. One whose lease lapsed while it waited was reclaimed elsewhere; running it here
        // too would scan the target twice.
        ScanEntity scan = repositoryScan();
        queueHolds(scan);
        when(queue.renewLease(anyLong(), anyString())).thenReturn(false);
        when(queue.countHeld(anyString())).thenReturn(0L);
        when(queue.reclaimLapsedLeases()).thenReturn(new ScanQueue.Reclaimed(List.of(), List.of()));
        ScanRunner runner = mock(ScanRunner.class);

        new ScanDispatcher(
                        queue, new TargetCatalog(repositories, containers), new CloneCredentials(gitTokens, sshKeys), mock(ScanIngestor.class),
                        new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of())),
                        settings, ruleSets, plugins, envelopes,
                        new ScanningProperties(Optional.of("linux/amd64")),
                        Optional.of(runner),
                        mock(AuditLogService.class),
                        mock(PlatformMetrics.class),
                        new TransactionTemplate(mock(PlatformTransactionManager.class)),
                        com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist.parse(""))
                .dispatch("worker-1", 2, List.of());

        verify(runner, never()).run(any());
        verify(queue, never()).fail(anyLong(), anyString(), anyString());
    }

    @Test
    @DisplayName("the remote lookups run before the writing transaction opens, not inside it")
    void lookupsPrecedeTheTransaction() {
        // End of life asks a public catalogue. Inside the transaction, that held the scan's row
        // lock — the one fencing a concurrent reclaim — for as long as the catalogue took.
        ScanEntity scan = repositoryScan();
        queueHolds(scan);
        when(queue.renewLease(anyLong(), anyString())).thenReturn(true);
        when(queue.holdForWrite(anyLong(), anyString())).thenReturn(true);
        when(queue.lease()).thenReturn(Duration.ofMinutes(20));
        when(queue.byId(scan.getId())).thenReturn(Optional.of(scan));
        when(queue.countHeld(anyString())).thenReturn(0L);
        when(queue.reclaimLapsedLeases()).thenReturn(new ScanQueue.Reclaimed(List.of(), List.of()));
        ScanIngestor ingestor = mock(ScanIngestor.class);
        when(ingestor.prepare(any(), any())).thenReturn(new ScanIngestor.Prepared(Optional.empty(), Optional.empty(), java.time.Instant.EPOCH));
        when(ingestor.ingest(any(), any(), any())).thenReturn(new ScanIngestor.Reconciliation(0, 0, 0, 0, List.of()));
        ScanRunner runner = mock(ScanRunner.class);
        when(runner.run(any())).thenReturn(ScanArtifacts.builder().secrets(List.of()).build(Duration.ofSeconds(1)));
        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

        new ScanDispatcher(
                        queue, new TargetCatalog(repositories, containers), new CloneCredentials(gitTokens, sshKeys), ingestor,
                        new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of())),
                        settings, ruleSets, plugins, envelopes,
                        new ScanningProperties(Optional.of("linux/amd64")),
                        Optional.of(runner),
                        mock(AuditLogService.class),
                        mock(PlatformMetrics.class),
                        new TransactionTemplate(manager),
                        com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist.parse(""))
                .dispatch("worker-1", 1, List.of());

        InOrder order = inOrder(ingestor, manager);
        order.verify(ingestor).prepare(any(), any());
        order.verify(manager).getTransaction(any());
        order.verify(ingestor).ingest(any(), any(), any());
    }

    /** Runs one scan through the dispatcher with a stubbed runner, and returns the row written. */
    private ScanEntity withRunner(ScanArtifacts artifacts) {
        ScanRunner runner = mock(ScanRunner.class);
        when(runner.run(any())).thenReturn(artifacts);
        ScanEntity scan = repositoryScan();
        onTheWorker(scan, runner);
        return scan;
    }

    /** Runs {@code scan} through a dispatch round of the built-in worker, with {@code runner} as its runner. */
    private void onTheWorker(ScanEntity scan, ScanRunner runner) {
        queueHolds(scan);
        when(queue.renewLease(anyLong(), anyString())).thenReturn(true);
        when(queue.holdForWrite(anyLong(), anyString())).thenReturn(true);
        when(queue.lease()).thenReturn(Duration.ofMinutes(20));
        when(queue.byId(scan.getId())).thenReturn(Optional.of(scan));
        when(queue.countHeld(anyString())).thenReturn(0L);
        when(queue.reclaimLapsedLeases()).thenReturn(new ScanQueue.Reclaimed(List.of(), List.of()));

        ScanIngestor ingestor = mock(ScanIngestor.class);
        when(ingestor.prepare(any(), any())).thenReturn(new ScanIngestor.Prepared(Optional.empty(), Optional.empty(), java.time.Instant.EPOCH));
        when(ingestor.ingest(any(), any(), any())).thenReturn(new ScanIngestor.Reconciliation(0, 0, 0, 0, List.of()));

        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

        new ScanDispatcher(
                        queue, new TargetCatalog(repositories, containers), new CloneCredentials(gitTokens, sshKeys), ingestor,
                        new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of())),
                        settings, ruleSets, plugins, envelopes,
                        new ScanningProperties(Optional.of("linux/amd64")),
                        Optional.of(runner),
                        mock(AuditLogService.class),
                        mock(PlatformMetrics.class),
                        new TransactionTemplate(manager),
                        com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist.parse(""))
                .dispatch("worker-1", 2, List.of());
    }

    /**
     * Repository 1's scan waits, and the queue honours an exclusion as the real one does: left out,
     * nothing comes back; not left out, the scan is taken. So a dispatcher that forgot to exclude
     * takes it — and the test sees a claim where there should have been none.
     */
    private void queueWaitsForRepositoryOne() {
        when(repositories.findAllById(any())).thenAnswer(call -> List.of(repositories.findById(1L).orElseThrow()));
        when(queue.claimWithin(any(), anyInt(), any(), any())).thenAnswer(call ->
                call.<ScanQueue.Exclusion>getArgument(3).among(Set.of(1L)).contains(1L)
                        ? new ScanQueue.AgentClaim(Optional.empty(), true)
                        : new ScanQueue.AgentClaim(Optional.of(repositoryScan()), false));
    }

    /** An exclusion that, asked about repository 1 as the queue's walk would ask, keeps it out. */
    private static org.mockito.ArgumentMatcher<ScanQueue.Exclusion> keepsRepositoryOne() {
        return exclusion -> exclusion != null && exclusion.among(Set.of(1L)).contains(1L);
    }

    private void queueHolds(ScanEntity scan) {
        when(queue.claim(anyInt(), anyString(), any())).thenReturn(List.of(scan));
        when(queue.claimWithin(any(), anyInt(), any(), any())).thenReturn(new ScanQueue.AgentClaim(Optional.of(scan), false));
    }

    private static ScanTask.Target.Repository repositoryTarget(ScanTask task) {
        return (ScanTask.Target.Repository) task.target();
    }

    private static ScanEntity repositoryScan() {
        ScanEntity scan = new ScanEntity();
        scan.setId(7L);
        scan.setRepoId(1L);
        return scan;
    }

    private static ScanEntity imageScan() {
        ScanEntity scan = new ScanEntity();
        scan.setId(8L);
        scan.setContainerId(4L);
        return scan;
    }

    private static final UUID TOKEN_ID = UUID.fromString("00000000-0000-0000-0000-0000000000cc");

    private void repositoryUsesAnHttpsToken() {
        RepositoryEntity https = new RepositoryEntity();
        https.setId(1L);
        https.setUrl("https://gitlab.example.com/team/service.git");
        https.setBranch("main");
        https.setHttpsTokenId(TOKEN_ID);
        when(repositories.findById(1L)).thenReturn(Optional.of(https));
        com.asmolabs.vectispire.core.targets.persistence.GitTokenEntity token = new com.asmolabs.vectispire.core.targets.persistence.GitTokenEntity();
        token.setId(TOKEN_ID);
        token.setName("gitlab");
        token.setHost("gitlab.example.com");
        token.setToken(new SecretCipher().encrypt(
                com.asmolabs.vectispire.common.domain.crypto.EncryptionKey.derive(ENCRYPTION_KEY),
                "glpat-secret",
                SecretCipher.gitTokenContext(TOKEN_ID.toString())));
        when(gitTokens.findById(TOKEN_ID)).thenReturn(Optional.of(token));
    }

    @Test
    @DisplayName("an HTTPS token is sealed for a delegated agent, with its host in the clear")
    void anHttpsTokenIsSealedLikeAKey() {
        repositoryUsesAnHttpsToken();
        queueHolds(repositoryScan());
        SealedEnvelope.KeyPair recipient = envelopes.generateKeyPair();

        ScanTask task = dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, recipient.publicKey()))
                .orElseThrow().task();

        ScanTask.Target.HttpsCredential https = repositoryTarget(task).https();
        assertThat(https.host()).isEqualTo("gitlab.example.com");
        assertThat(SealedEnvelope.isSealed(https.token())).isTrue();
        assertThat(envelopes.open(recipient, https.token())).contains("glpat-secret");
    }

    @Test
    @DisplayName("an agent in local mode never receives the token, which is never even decrypted")
    void localModeGetsNoToken() {
        repositoryUsesAnHttpsToken();
        queueHolds(repositoryScan());

        ScanTask task = dispatcher.claimForAgent(agent(CredentialsMode.LOCAL, null)).orElseThrow().task();

        assertThat(repositoryTarget(task).https()).isNull();
        verify(gitTokens, never()).findById(any());
    }

    @Test
    @DisplayName("a token with no verified sealing key to seal it for is withheld, like a key")
    void anUnsealedTokenIsWithheld() {
        repositoryUsesAnHttpsToken();
        queueWaitsForRepositoryOne();

        assertThatThrownBy(() -> dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null)))
                .isInstanceOf(CredentialWithheldException.class);
        verify(queue).claimWithin(any(), anyInt(), any(), argThat(keepsRepositoryOne()));
        verify(gitTokens, never()).findById(any());
    }

    @Test
    @DisplayName("a repository on a host the allowlist does not name is not handed to any executor")
    void anUnlistedHostIsNotScanned() {
        // Checked at dispatch as well as at entry: a list tightened after the repository was
        // registered must stop its scans too.
        queueHolds(repositoryScan());
        PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        ScanDispatcher restricted = new ScanDispatcher(
                queue, new TargetCatalog(repositories, containers), new CloneCredentials(gitTokens, sshKeys), mock(ScanIngestor.class),
                new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of())),
                settings, ruleSets, plugins, envelopes, new ScanningProperties(Optional.of("linux/amd64")),
                Optional.empty(), mock(AuditLogService.class), mock(PlatformMetrics.class),
                new TransactionTemplate(transactions),
                com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist.parse("gitlab.corp.example"));

        assertThat(restricted.claimForAgent(agent(CredentialsMode.LOCAL, null))).isEmpty();
        verify(queue).fail(eq(7L), anyString(), org.mockito.ArgumentMatchers.contains("is not allowed"));
    }

    @Test
    @DisplayName("a stored URL the clone would read as another host is refused before it is dispatched")
    void anAmbiguousStoredUrlIsNotDispatched() {
        // A row registered before the rule: java.net.URI reads one host, JGit another. Refused
        // here, with no allowlist at all, before the task — and a credential — leave for an agent.
        RepositoryEntity ambiguous = repository();
        ambiguous.setUrl("https://forge.example#@elsewhere.example/team/service.git");
        ambiguous.setSshKeyId(null);
        when(repositories.findById(1L)).thenReturn(Optional.of(ambiguous));
        queueHolds(repositoryScan());

        assertThat(dispatcher.claimForAgent(agent(CredentialsMode.LOCAL, null))).isEmpty();
        verify(queue).fail(eq(7L), anyString(), org.mockito.ArgumentMatchers.contains("Repository URL refused"));
    }

    private static final List<com.asmolabs.vectispire.common.domain.plugins.PluginRef> PLUGINS = List.of(
            new com.asmolabs.vectispire.common.domain.plugins.PluginRef("acme-lint", "a".repeat(64)),
            new com.asmolabs.vectispire.common.domain.plugins.PluginRef("acme-sarif", "b".repeat(64)));

    /** Which credentials repository 1 carries. */
    private enum Carries {
        SSH_KEY,
        HTTPS_TOKEN,
        BOTH
    }

    /**
     * Repository 1 with every field of its task set to something other than its default — a rule
     * set, SAST, a sub-path, a branch asked by the scan, two plugins — and the credentials asked for.
     * Returns the task the built-in worker must receive: the clear one, written out here rather than
     * read off the dispatcher, so that a rebuild dropping a field cannot also drop it from the
     * expectation.
     */
    private ScanTask everyFieldCarrying(Carries carries) {
        repositoryUsesAnHttpsToken();
        RepositoryEntity repository = repositories.findById(1L).orElseThrow();
        repository.setSubPath("services/api");
        if (carries == Carries.SSH_KEY) {
            repository.setHttpsTokenId(null);
        }
        if (carries != Carries.HTTPS_TOKEN) {
            repository.setSshKeyId(KEY_ID);
        }
        when(ruleSets.activeHash()).thenReturn(Optional.of("f".repeat(64)));
        when(settings.isEnabled(Setting.SAST_ENABLED)).thenReturn(true);
        when(plugins.forRepository(1L)).thenReturn(PLUGINS);
        return new ScanTask(
                new ScanTask.Target.Repository(
                        "https://gitlab.example.com/team/service.git",
                        "release",
                        "services/api",
                        carries == Carries.HTTPS_TOKEN ? null : PRIVATE_KEY,
                        carries == Carries.SSH_KEY
                                ? null
                                : new ScanTask.Target.HttpsCredential("gitlab.example.com", null, "glpat-secret")),
                "f".repeat(64),
                Set.of(ScanTask.Step.DEPENDENCIES, ScanTask.Step.SECRETS, ScanTask.Step.IAC, ScanTask.Step.SAST),
                PLUGINS);
    }

    private static ScanEntity scanOfBranch(String branch) {
        ScanEntity scan = repositoryScan();
        scan.setBranch(branch);
        return scan;
    }

    /**
     * Sealing a credential rebuilds the task, and a rebuild names the fields it copies: one that
     * forgot the plugins would have a credentialed repository scanned by a remote agent run none of
     * them, and every plugin read as absent — a failure — on a scan that never tried it. So the
     * whole record is compared, the sealed fields aside: the next field added to the task is dropped
     * in exactly the same way.
     */
    @org.junit.jupiter.params.ParameterizedTest(name = "{0}")
    @org.junit.jupiter.params.provider.EnumSource(Carries.class)
    @DisplayName("sealing a credential for an agent keeps the rest of the task, its plugins included")
    void sealingKeepsTheWholeTask(Carries carries) {
        ScanTask clear = everyFieldCarrying(carries);
        queueHolds(scanOfBranch("release"));
        SealedEnvelope.KeyPair recipient = envelopes.generateKeyPair();

        ScanTask delivered = dispatcher
                .claimForAgent(agent(CredentialsMode.DELEGATED, recipient.publicKey()))
                .orElseThrow()
                .task();

        assertThat(delivered.plugins()).containsExactlyElementsOf(PLUGINS);
        assertThat(delivered)
                .usingRecursiveComparison()
                .ignoringFields("target.privateKey", "target.https.token")
                .isEqualTo(clear);
        ScanTask.Target.Repository target = repositoryTarget(delivered);
        ScanTask.Target.Repository expected = repositoryTarget(clear);
        if (expected.privateKey() != null) {
            assertThat(envelopes.open(recipient, target.privateKey())).contains(PRIVATE_KEY);
        } else {
            assertThat(target.privateKey()).isNull();
        }
        if (expected.https() != null) {
            assertThat(envelopes.open(recipient, target.https().token())).contains("glpat-secret");
        } else {
            assertThat(target.https()).isNull();
        }
    }

    @org.junit.jupiter.params.ParameterizedTest(name = "{0}")
    @org.junit.jupiter.params.provider.EnumSource(Carries.class)
    @DisplayName("the built-in worker receives the whole task in the clear, its plugins included")
    void theWorkerRunsTheWholeTask(Carries carries) {
        ScanTask clear = everyFieldCarrying(carries);
        ScanRunner runner = mock(ScanRunner.class);
        when(runner.run(any())).thenReturn(ScanArtifacts.builder().secrets(List.of()).build(Duration.ofSeconds(1)));

        onTheWorker(scanOfBranch("release"), runner);

        org.mockito.ArgumentCaptor<ScanTask> ran = org.mockito.ArgumentCaptor.forClass(ScanTask.class);
        verify(runner).run(ran.capture());
        assertThat(ran.getValue()).isEqualTo(clear);
    }

    private static RepositoryEntity repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setId(1L);
        repository.setUrl("git@example.invalid:team/service.git");
        repository.setBranch("main");
        repository.setSshKeyId(KEY_ID);
        return repository;
    }

    private static ContainerEntity container() {
        ContainerEntity container = new ContainerEntity();
        container.setId(4L);
        container.setImageName("team/service");
        container.setTag("1.4.0");
        return container;
    }

    private static SshKeyEntity sshKey() {
        SshKeyEntity key = new SshKeyEntity();
        key.setId(KEY_ID);
        key.setName("deploy");
        key.setPrivateKey(new SecretCipher()
                .encrypt(
                        com.asmolabs.vectispire.common.domain.crypto.EncryptionKey.derive(ENCRYPTION_KEY),
                        PRIVATE_KEY,
                        SecretCipher.privateKeyContext(KEY_ID.toString())));
        return key;
    }

    private static AgentView agent(CredentialsMode mode, String sealingPublicKey) {
        return com.asmolabs.vectispire.core.agents.internal.AgentViews.of(agentRow(mode, sealingPublicKey));
    }

    private static AgentEntity agentRow(CredentialsMode mode, String sealingPublicKey) {
        AgentEntity agent = new AgentEntity();
        agent.setId(UUID.fromString("00000000-0000-0000-0000-0000000000bb"));
        agent.setCredentialsMode(mode.wireName());
        agent.setSealingPublicKey(sealingPublicKey);
        return agent;
    }
}
