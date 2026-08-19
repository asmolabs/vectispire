package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.agents.CredentialsMode;
import com.asmolabs.zanshin.common.domain.crypto.SealedEnvelope;
import com.asmolabs.zanshin.common.domain.crypto.SecretCipher;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.common.domain.scans.ScanStatus;
import com.asmolabs.zanshin.common.scanning.ScanArtifacts;
import com.asmolabs.zanshin.common.scanning.ScanRunner;
import com.asmolabs.zanshin.common.scanning.ScanTask;
import com.asmolabs.zanshin.core.persistence.AgentEntity;
import com.asmolabs.zanshin.core.persistence.ContainerEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.persistence.SshKeyEntity;
import com.asmolabs.zanshin.core.repositories.Containers;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.ScanQueue;
import com.asmolabs.zanshin.core.repositories.SshKeys;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
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
    private static final String PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private static final String ENCRYPTION_KEY = "Y3VycmVudC1rZXktMzItYnl0ZXMtbG9uZy0xMjM0NQ==";

    private final SealedEnvelope envelopes = new SealedEnvelope();

    private ScanQueue queue;
    private GitRepositories repositories;
    private Containers containers;
    private SshKeys sshKeys;
    private SettingsService settings;
    private RuleSetService ruleSets;
    private ScanDispatcher dispatcher;

    @BeforeEach
    void wire() {
        queue = mock(ScanQueue.class);
        repositories = mock(GitRepositories.class);
        containers = mock(Containers.class);
        sshKeys = mock(SshKeys.class);
        settings = mock(SettingsService.class);
        ruleSets = mock(RuleSetService.class);

        when(ruleSets.active()).thenReturn(Optional.empty());
        when(settings.isEnabled(any())).thenReturn(false);
        when(repositories.findById(1L)).thenReturn(Optional.of(repository()));
        when(sshKeys.findById(KEY_ID)).thenReturn(Optional.of(sshKey()));

        PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

        dispatcher = new ScanDispatcher(
                queue,
                repositories,
                containers,
                sshKeys,
                mock(ScanIngestor.class),
                new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of())),
                settings,
                ruleSets,
                envelopes,
                new ScanningProperties(Optional.of("linux/amd64")),
                Optional.empty(),
                new TransactionTemplate(transactions));
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
        verify(queue, never()).requeue(anyLong());
    }

    @Test
    @DisplayName("an older agent with no sealing key still needs an encrypted link")
    void unsealedKeyOverAnOpenLinkIsRefused() {
        queueHolds(repositoryScan());

        assertThatThrownBy(() -> dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null), false))
                .isInstanceOf(InsecureCredentialTransportException.class);

        // Put back before refusing: otherwise the scan stays claimed by an agent that received
        // nothing, and waits out the whole lease before anybody can take it.
        verify(queue).requeue(7L);
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
        AgentEntity agent = agent(CredentialsMode.DELEGATED, null);
        agent.setCredentialsMode("something-a-later-version-wrote");

        ScanTask task = dispatcher.claimForAgent(agent, true).orElseThrow().task();

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
        verify(queue, never()).requeue(anyLong());
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
    @DisplayName("a deleted SSH key fails the scan rather than cloning anonymously")
    void aMissingKeyFailsTheScan() {
        queueHolds(repositoryScan());
        when(sshKeys.findById(KEY_ID)).thenReturn(Optional.empty());

        assertThat(dispatcher.claimForAgent(agent(CredentialsMode.DELEGATED, null), true)).isEmpty();
        verify(queue).fail(anyLong(), anyString());
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
    @DisplayName("a step that ran and found nothing keeps the scan completed")
    void aCleanScanStaysCompleted() {
        // Absent is not empty. If an empty result counted as "examined nothing", every clean
        // target would be reported as a failure — the opposite mistake, and a louder one.
        ScanEntity scan = withRunner(
                ScanArtifacts.builder().secrets(List.of()).build(Duration.ofSeconds(2)));

        assertThat(scan.getStatus()).isEqualTo(ScanStatus.COMPLETED.wireName());
    }

    /** Runs one scan through the dispatcher with a stubbed runner, and returns the row written. */
    private ScanEntity withRunner(ScanArtifacts artifacts) {
        ScanEntity scan = repositoryScan();
        queueHolds(scan);
        when(queue.stillOwned(anyLong(), anyString())).thenReturn(true);
        when(queue.byId(scan.getId())).thenReturn(Optional.of(scan));
        when(queue.countRunning()).thenReturn(0L);
        when(queue.reclaimLapsedLeases()).thenReturn(new ScanQueue.Reclaimed(List.of(), List.of()));

        ScanIngestor ingestor = mock(ScanIngestor.class);
        when(ingestor.ingest(any(), any())).thenReturn(new IssueSyncService.SyncResult(0, 0, 0, 0, List.of(), List.of()));

        ScanRunner runner = mock(ScanRunner.class);
        when(runner.run(any())).thenReturn(artifacts);

        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

        new ScanDispatcher(
                        queue, repositories, containers, sshKeys, ingestor,
                        new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of())),
                        settings, ruleSets, envelopes,
                        new ScanningProperties(Optional.of("linux/amd64")),
                        Optional.of(runner),
                        new TransactionTemplate(manager))
                .dispatch("worker-1", 2, List.of());

        return scan;
    }

    private void queueHolds(ScanEntity scan) {
        when(queue.claim(anyInt(), anyString(), any())).thenReturn(List.of(scan));
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
                        com.asmolabs.zanshin.common.domain.crypto.EncryptionKey.derive(ENCRYPTION_KEY),
                        PRIVATE_KEY,
                        SecretCipher.privateKeyContext(KEY_ID.toString())));
        return key;
    }

    private static AgentEntity agent(CredentialsMode mode, String sealingPublicKey) {
        AgentEntity agent = new AgentEntity();
        agent.setId(UUID.fromString("00000000-0000-0000-0000-0000000000bb"));
        agent.setCredentialsMode(mode.wireName());
        agent.setSealingPublicKey(sealingPublicKey);
        return agent;
    }
}
