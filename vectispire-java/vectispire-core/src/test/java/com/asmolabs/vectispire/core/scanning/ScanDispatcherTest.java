package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
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
import com.asmolabs.vectispire.core.targets.persistence.Containers;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeys;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
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
    private GitRepositories repositories;
    private Containers containers;
    private SshKeys sshKeys;
    private com.asmolabs.vectispire.core.targets.persistence.GitTokens gitTokens;
    private SettingsService settings;
    private ScanRuleSets ruleSets;
    private ScanDispatcher dispatcher;

    @BeforeEach
    void wire() {
        queue = mock(ScanQueue.class);
        repositories = mock(GitRepositories.class);
        containers = mock(Containers.class);
        sshKeys = mock(SshKeys.class);
        gitTokens = mock(com.asmolabs.vectispire.core.targets.persistence.GitTokens.class);
        settings = mock(SettingsService.class);
        ruleSets = mock(ScanRuleSets.class);

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
                envelopes,
                new ScanningProperties(Optional.of("linux/amd64")),
                Optional.empty(),
                mock(AuditLogService.class),
                mock(PlatformMetrics.class),
                new TransactionTemplate(transactions),
                com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist.parse(""));
    }

    @Test
    @DisplayName("an agent in local mode never receives a deployment key")
    void localModeGetsNoKey() {
        queueHolds(repositoryScan());

        ScanTask task = dispatcher.claimForAgent(agent(CredentialsMode.LOCAL, null), true).orElseThrow().task();

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
                .claimForAgent(agent(CredentialsMode.DELEGATED, recipient.publicKey()), false)
                .orElseThrow()
                .task();

        String delivered = repositoryTarget(task).privateKey();
        assertThat(SealedEnvelope.isSealed(delivered)).isTrue();
        assertThat(envelopes.open(recipient, delivered)).contains(PRIVATE_KEY);
    }

    @Test
    @DisplayName("sealing removes the encrypted-transport requirement, because the proxy no longer sees the key")
    void sealingReplacesTheTransportRequirement() {
        queueHolds(repositoryScan());

        assertThat(dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, envelopes.generateKeyPair().publicKey()), false))
                .isPresent();
        verify(queue, never()).requeue(anyLong(), anyString());
    }

    @Test
    @DisplayName("an older agent with no sealing key still needs an encrypted link")
    void unsealedKeyOverAnOpenLinkIsRefused() {
        queueHolds(repositoryScan());

        assertThatThrownBy(() -> dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null), false))
                .isInstanceOf(InsecureCredentialTransportException.class);

        // Put back before refusing: otherwise the scan stays claimed by an agent that received
        // nothing, and waits out the whole lease before anybody can take it.
        verify(queue).requeue(eq(7L), anyString());
    }

    @Test
    void unsealedKeyOverAnEncryptedLinkIsDelivered() {
        queueHolds(repositoryScan());

        ScanTask task = dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null), true).orElseThrow().task();

        assertThat(repositoryTarget(task).privateKey()).isEqualTo(PRIVATE_KEY);
    }

    @Test
    @DisplayName("an unreadable credentials mode reads as local")
    void anUnknownModeDeliversNothing() {
        queueHolds(repositoryScan());
        AgentEntity agent = agentRow(CredentialsMode.DELEGATED, null);
        agent.setCredentialsMode("something-a-later-version-wrote");

        ScanTask task = dispatcher.claimForAgent(com.asmolabs.vectispire.core.agents.internal.AgentViews.of(agent), true).orElseThrow().task();

        assertThat(repositoryTarget(task).privateKey()).isNull();
    }

    @Test
    @DisplayName("an image scan carries no key whatever the agent's mode")
    void imageScansCarryNoCredentials() {
        queueHolds(imageScan());
        when(containers.findById(4L)).thenReturn(Optional.of(container()));

        ScanTask task = dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null), false).orElseThrow().task();

        assertThat(task.target()).isInstanceOf(ScanTask.Target.Image.class);
        // No refusal either: with nothing to protect, the encrypted-link precaution does not
        // apply, and an image scan stays distributable to any agent.
        verify(queue, never()).requeue(anyLong(), anyString());
    }

    @Test
    @DisplayName("the SAST step is on the task only when the setting says so")
    void sastIsDecidedByTheControlPlane() {
        queueHolds(repositoryScan());
        assertThat(dispatcher.claimForAgent(agent(CredentialsMode.LOCAL, null), true).orElseThrow().task().steps())
                .doesNotContain(ScanTask.Step.SAST);

        when(settings.isEnabled(Setting.SAST_ENABLED)).thenReturn(true);
        queueHolds(repositoryScan());
        assertThat(dispatcher.claimForAgent(agent(CredentialsMode.LOCAL, null), true).orElseThrow().task().steps())
                .contains(ScanTask.Step.SAST);
    }

    @Test
    @DisplayName("an agent's claim is held to its limit as the queue applies it, never to the raw column")
    void anAgentClaimsWithinItsEffectiveLimit() {
        queueHolds(imageScan());
        AgentEntity agent = agentRow(CredentialsMode.LOCAL, null);

        agent.setMaxConcurrent(4);
        dispatcher.claimForAgent(com.asmolabs.vectispire.core.agents.internal.AgentViews.of(agent), true);
        verify(queue).claimWithin(agent.getId(), 4, List.of());

        // A row from before the bound: 50 is applied as 16, and nothing — null or zero — as a
        // paused agent.
        agent.setMaxConcurrent(50);
        dispatcher.claimForAgent(com.asmolabs.vectispire.core.agents.internal.AgentViews.of(agent), true);
        verify(queue).claimWithin(agent.getId(), 16, List.of());

        agent.setMaxConcurrent(0);
        dispatcher.claimForAgent(com.asmolabs.vectispire.core.agents.internal.AgentViews.of(agent), true);
        verify(queue).claimWithin(agent.getId(), 1, List.of());
    }

    @Test
    @DisplayName("a deleted SSH key fails the scan rather than cloning anonymously")
    void aMissingKeyFailsTheScan() {
        queueHolds(repositoryScan());
        when(sshKeys.findById(KEY_ID)).thenReturn(Optional.empty());

        assertThat(dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null), true)).isEmpty();
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
        when(queue.countRunning()).thenReturn(0L);
        when(queue.reclaimLapsedLeases()).thenReturn(new ScanQueue.Reclaimed(List.of(), List.of()));
        ScanRunner runner = mock(ScanRunner.class);

        new ScanDispatcher(
                        queue, new TargetCatalog(repositories, containers), new CloneCredentials(gitTokens, sshKeys), mock(ScanIngestor.class),
                        new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of())),
                        settings, ruleSets, envelopes,
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
        when(queue.countRunning()).thenReturn(0L);
        when(queue.reclaimLapsedLeases()).thenReturn(new ScanQueue.Reclaimed(List.of(), List.of()));
        ScanIngestor ingestor = mock(ScanIngestor.class);
        when(ingestor.prepare(any(), any())).thenReturn(new ScanIngestor.Prepared(Optional.empty(), java.time.Instant.EPOCH));
        when(ingestor.ingest(any(), any(), any())).thenReturn(new ScanIngestor.Reconciliation(0, 0, 0, 0, List.of()));
        ScanRunner runner = mock(ScanRunner.class);
        when(runner.run(any())).thenReturn(ScanArtifacts.builder().secrets(List.of()).build(Duration.ofSeconds(1)));
        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

        new ScanDispatcher(
                        queue, new TargetCatalog(repositories, containers), new CloneCredentials(gitTokens, sshKeys), ingestor,
                        new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of())),
                        settings, ruleSets, envelopes,
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
        ScanEntity scan = repositoryScan();
        queueHolds(scan);
        when(queue.renewLease(anyLong(), anyString())).thenReturn(true);
        when(queue.holdForWrite(anyLong(), anyString())).thenReturn(true);
        when(queue.lease()).thenReturn(Duration.ofMinutes(20));
        when(queue.byId(scan.getId())).thenReturn(Optional.of(scan));
        when(queue.countRunning()).thenReturn(0L);
        when(queue.reclaimLapsedLeases()).thenReturn(new ScanQueue.Reclaimed(List.of(), List.of()));

        ScanIngestor ingestor = mock(ScanIngestor.class);
        when(ingestor.prepare(any(), any())).thenReturn(new ScanIngestor.Prepared(Optional.empty(), java.time.Instant.EPOCH));
        when(ingestor.ingest(any(), any(), any())).thenReturn(new ScanIngestor.Reconciliation(0, 0, 0, 0, List.of()));

        ScanRunner runner = mock(ScanRunner.class);
        when(runner.run(any())).thenReturn(artifacts);

        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

        new ScanDispatcher(
                        queue, new TargetCatalog(repositories, containers), new CloneCredentials(gitTokens, sshKeys), ingestor,
                        new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of())),
                        settings, ruleSets, envelopes,
                        new ScanningProperties(Optional.of("linux/amd64")),
                        Optional.of(runner),
                        mock(AuditLogService.class),
                        mock(PlatformMetrics.class),
                        new TransactionTemplate(manager),
                        com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist.parse(""))
                .dispatch("worker-1", 2, List.of());

        return scan;
    }

    private void queueHolds(ScanEntity scan) {
        when(queue.claim(anyInt(), anyString(), any())).thenReturn(List.of(scan));
        when(queue.claimWithin(any(), anyInt(), any())).thenReturn(Optional.of(scan));
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

        ScanTask task = dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, recipient.publicKey()), false)
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

        ScanTask task = dispatcher.claimForAgent(agent(CredentialsMode.LOCAL, null), true).orElseThrow().task();

        assertThat(repositoryTarget(task).https()).isNull();
        verify(gitTokens, never()).findById(any());
    }

    @Test
    @DisplayName("an unsealed token over an open link is refused, like a key")
    void anUnsealedTokenOverAnOpenLinkIsRefused() {
        repositoryUsesAnHttpsToken();
        queueHolds(repositoryScan());

        assertThatThrownBy(() -> dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null), false))
                .isInstanceOf(InsecureCredentialTransportException.class);
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
                settings, ruleSets, envelopes, new ScanningProperties(Optional.of("linux/amd64")),
                Optional.empty(), mock(AuditLogService.class), mock(PlatformMetrics.class),
                new TransactionTemplate(transactions),
                com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist.parse("gitlab.corp.example"));

        assertThat(restricted.claimForAgent(agent(CredentialsMode.LOCAL, null), true)).isEmpty();
        verify(queue).fail(eq(7L), anyString(), org.mockito.ArgumentMatchers.contains("is not allowed"));
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
