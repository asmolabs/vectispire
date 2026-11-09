package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.InspectImageCmd;
import com.github.dockerjava.api.command.LogContainerCmd;
import com.github.dockerjava.api.command.WaitContainerResultCallback;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.api.model.StreamType;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What a scanner may write before the process reading it stops listening.
 *
 * <p>The scanners read content somebody else wrote, and print what it makes them print; the output
 * used to be kept whole, in the heap of the worker — in the built-in worker, the control plane's.
 */
@DisplayName("the output a scanner container may write")
class ContainerOutputLimitTest {

    @Test
    @DisplayName("a scanner writing past the ceiling fails its step instead of filling the heap")
    void outputPastTheCeilingFailsTheStep() throws Exception {
        ContainerRunner runner = runnerWhoseScannerWrites(4, 1024, 3 * 1024);

        assertThatThrownBy(() -> runner.run(ContainerRun.of("scanner:pinned", List.of(), List.of(), "probe")))
                .isInstanceOf(ScannerFailureException.class)
                .hasMessageContaining("wrote more than 3072 bytes");
    }

    @Test
    @DisplayName("output within the ceiling is handed over whole")
    void outputWithinTheCeilingIsKept() throws Exception {
        ContainerRunner runner = runnerWhoseScannerWrites(3, 1024, 3 * 1024);

        assertThat(runner.run(ContainerRun.of("scanner:pinned", List.of(), List.of(), "probe")).stdout())
                .hasSize(3 * 1024);
    }

    @Test
    @DisplayName("the collector stops keeping output at the ceiling, and keeps only the start of the error stream")
    void theCollectorKeepsWithinItsBounds() throws Exception {
        ContainerRunner.StreamCollector collector = new ContainerRunner.StreamCollector(10, 4);

        collector.onNext(new Frame(StreamType.STDOUT, "0123456789".getBytes(StandardCharsets.UTF_8)));
        collector.onNext(new Frame(StreamType.STDERR, "warning: a".getBytes(StandardCharsets.UTF_8)));
        assertThat(collector.overflowed()).isFalse();

        collector.onNext(new Frame(StreamType.STDOUT, "!".getBytes(StandardCharsets.UTF_8)));
        collector.onNext(new Frame(StreamType.STDOUT, "more".getBytes(StandardCharsets.UTF_8)));

        assertThat(collector.overflowed()).isTrue();
        assertThat(collector.stdout()).isEqualTo("0123456789");
        assertThat(collector.stderr()).isEqualTo("warn");
    }

    /** A daemon stub whose container exits 0 having written {@code frames} frames of {@code frameBytes}. */
    private static ContainerRunner runnerWhoseScannerWrites(int frames, int frameBytes, long outputBytes) {
        DockerClient docker = mock(DockerClient.class, RETURNS_DEEP_STUBS);
        when(docker.inspectImageCmd(anyString())).thenReturn(mock(InspectImageCmd.class, RETURNS_DEEP_STUBS));
        CreateContainerCmd create = mock(CreateContainerCmd.class, RETURNS_SELF);
        CreateContainerResponse created = new CreateContainerResponse();
        created.setId("container-under-test");
        when(create.exec()).thenReturn(created);
        when(docker.createContainerCmd(anyString())).thenReturn(create);

        WaitContainerResultCallback exited = mock(WaitContainerResultCallback.class);
        when(exited.awaitStatusCode(anyLong(), any())).thenReturn(0);
        when(docker.waitContainerCmd(anyString()).start()).thenReturn(exited);

        LogContainerCmd logs = mock(LogContainerCmd.class, RETURNS_SELF);
        when(docker.logContainerCmd(anyString())).thenReturn(logs);
        when(logs.exec(any())).thenAnswer(invocation -> {
            ResultCallback<Frame> callback = invocation.getArgument(0);
            byte[] chunk = "x".repeat(frameBytes).getBytes(StandardCharsets.UTF_8);
            for (int i = 0; i < frames; i++) {
                callback.onNext(new Frame(StreamType.STDOUT, chunk));
            }
            callback.onComplete();
            return callback;
        });

        return new ContainerRunner(docker, new ScannerLimits(
                ScannerLimits.DEFAULT.memory(), 512, Duration.ofMinutes(1), 1_000_000_000L, outputBytes));
    }
}
