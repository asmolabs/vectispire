package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.InspectImageCmd;
import com.github.dockerjava.api.model.Capability;
import com.github.dockerjava.api.model.HostConfig;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * The confinement every scanner container is created with.
 *
 * <p><b>This is the most security-critical configuration in the project and nothing checked it.</b>
 * The flags were set in one place and read correct; that is not the same as being applied, and the
 * gap was not hypothetical — the published dimensioning view listed a CPU quota of "2.0 vCPUs" for
 * weeks while no CPU limit of any kind was applied. A control nobody checks is a control that can
 * be documented and absent at the same time.
 *
 * <p>Asserted on the {@link HostConfig} handed to the daemon rather than by starting a container:
 * what is under test is what Vectispire asks for. Whether the kernel honours it is the kernel's
 * business and not something a unit suite can pretend to verify.
 *
 * <p>These containers analyse hostile input by definition — the metadata of an image nobody
 * controls, a repository written by somebody else.
 */
@DisplayName("the confinement of a scanner container")
class ContainerHardeningTest {

    private CreateContainerCmd createCommand;
    private ContainerRunner runner;

    @BeforeEach
    void stubTheDaemon() {
        DockerClient docker = mock(DockerClient.class, RETURNS_DEEP_STUBS);

        // Present, so `run` does not try to pull.
        InspectImageCmd inspect = mock(InspectImageCmd.class, RETURNS_DEEP_STUBS);
        when(docker.inspectImageCmd(anyString())).thenReturn(inspect);

        // RETURNS_SELF so the fluent chain lands on one object: the request is built by a
        // sequence of `with…` calls, and capturing it means capturing what the last of them was
        // handed.
        createCommand = mock(CreateContainerCmd.class, RETURNS_SELF);
        CreateContainerResponse created = new CreateContainerResponse();
        created.setId("container-under-test");
        when(createCommand.exec()).thenReturn(created);
        when(docker.createContainerCmd(anyString())).thenReturn(createCommand);

        runner = new ContainerRunner(docker, ScannerLimits.DEFAULT);
    }

    @Test
    @DisplayName("every hardening flag is on the request, and the CPU share among them")
    void theHostConfigCarriesEveryFlag() {
        try {
            runner.run(ContainerRun.of("scanner:pinned", List.of("--version"), List.of(), "probe"));
        } catch (RuntimeException expected) {
            // The stub stops short of a running container; the request has already been built,
            // which is the whole of what this test is about.
        }

        HostConfig config = capturedHostConfig();

        assertThat(config.getCapDrop())
                .as("a scanner needs no capability at all, and dropping them is the cheapest "
                        + "escalation removed")
                .containsExactlyInAnyOrder(Capability.values());
        assertThat(config.getSecurityOpts())
                .as("no-new-privileges is what stops a setuid binary inside the image mattering")
                .contains("no-new-privileges");
        assertThat(config.getReadonlyRootfs())
                .as("a tool compromised mid-scan must not be able to keep a binary for the life "
                        + "of the container")
                .isTrue();
        assertThat(config.getNetworkMode())
                .as("no network unless the run asked for one — this run did not")
                .isEqualTo("none");
        assertThat(config.getMemory())
                .as("a container that exceeds this dies; the host does not")
                .isEqualTo(ScannerLimits.DEFAULT.memory());
        assertThat(config.getPidsLimit())
                .as("what turns a fork bomb into a dead container")
                .isEqualTo(ScannerLimits.DEFAULT.pids());

        // **The one that was documented and absent.** Asserted against the record rather than
        // against a literal, so the default can move without this test becoming a second opinion
        // about what it should be.
        assertThat(config.getNanoCPUs())
                .as("a repository nobody controls must not be able to take the last core and "
                        + "leave the control plane unable to answer a gate call")
                .isEqualTo(ScannerLimits.DEFAULT.nanoCpus());
        assertThat(ScannerLimits.DEFAULT.nanoCpus())
                .as("the default leaves a core for everything that is not a scanner, and is "
                        + "floored at one because a quota of zero means \"no limit\" to the daemon")
                .isGreaterThanOrEqualTo(1_000_000_000L);

        assertThat(config.getTmpFs())
                .as("read-only takes scratch space away and every one of these tools needs it "
                        + "back — noexec, so it is not somewhere to stage a payload")
                .allSatisfy((path, options) -> assertThat(options).contains("noexec").contains("nosuid"));
    }

    @Test
    @DisplayName("a run that asks for the network gets it, and nothing else loosens with it")
    void networkIsTheOnlyThingARunCanOpen() {
        // Grype must reach its vulnerability database; that is the one exception, and it must
        // stay the only one. A request that could also drop the read-only root or the PID cap
        // would make the exception a hole.
        try {
            runner.run(ContainerRun.of("scanner:pinned", List.of("db", "update"), List.of(), "probe")
                    .withNetwork());
        } catch (RuntimeException expected) {
            // As above.
        }

        HostConfig config = capturedHostConfig();
        assertThat(config.getNetworkMode()).isEqualTo("bridge");
        assertThat(config.getReadonlyRootfs()).isTrue();
        assertThat(config.getCapDrop()).containsExactlyInAnyOrder(Capability.values());
        assertThat(config.getNanoCPUs()).isEqualTo(ScannerLimits.DEFAULT.nanoCpus());
    }

    private HostConfig capturedHostConfig() {
        ArgumentCaptor<HostConfig> captor = ArgumentCaptor.forClass(HostConfig.class);
        org.mockito.Mockito.verify(createCommand).withHostConfig(captor.capture());
        return captor.getValue();
    }

    @Test
    @DisplayName("the timeout is a ceiling a run may lower and not raise")
    void aRunCannotOutlastTheCeiling() {
        // The timeout is what bounds how long a saturating scanner lasts, and the CPU share is
        // what bounds how much it takes while it does. Neither is sufficient alone, which is why
        // the default carries both.
        assertThat(ScannerLimits.DEFAULT.timeout()).isEqualTo(Duration.ofMinutes(15));
    }
}
