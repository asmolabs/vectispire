package com.asmolabs.vectispire.agent.kubernetes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ExecChannelsTest {

    private final ObjectMapper json = new ObjectMapper();

    private static ByteBuffer message(int channel, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(bytes.length + 1).put((byte) channel).put(bytes).flip();
    }

    private static ByteBuffer bytes(String text) {
        return ByteBuffer.wrap(text.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void sortsMessagesByTheirFirstByte() {
        ExecChannels channels = new ExecChannels(1024);
        channels.accept(message(1, "out"), true);
        channels.accept(message(2, "err"), true);
        channels.accept(message(1, "put"), true);
        channels.accept(message(3, "{\"status\":\"Success\"}"), true);

        assertThat(new String(channels.stdout(), StandardCharsets.UTF_8)).isEqualTo("output");
        assertThat(channels.stderr()).isEqualTo("err");
        assertThat(channels.exitCode(json)).contains(0);
    }

    @Test
    void onlyTheFirstFragmentOfAMessageNamesItsChannel() {
        // A report delivered in pieces: the second piece starts with a byte that would read as "stderr".
        ExecChannels channels = new ExecChannels(1024);
        channels.accept(message(1, "{\"a\""), false);
        channels.accept(bytes("\u0002:1}"), true);

        assertThat(new String(channels.stdout(), StandardCharsets.UTF_8)).isEqualTo("{\"a\"\u0002:1}");
        assertThat(channels.stderr()).isEmpty();
    }

    @Test
    void anEmptyFirstFragmentDoesNotConsumeTheChannel() {
        ExecChannels channels = new ExecChannels(1024);
        channels.accept(ByteBuffer.allocate(0), false);
        channels.accept(message(2, "late"), true);

        assertThat(channels.stderr()).isEqualTo("late");
    }

    @Test
    void passingTheCeilingIsSaidAndStopsTheReading() {
        ExecChannels channels = new ExecChannels(4);
        assertThat(channels.accept(message(1, "1234"), true)).isTrue();
        assertThat(channels.overCeiling()).isFalse();

        assertThat(channels.accept(message(1, "56789abcdef"), true)).isFalse();
        assertThat(channels.overCeiling()).isTrue();
        // Never more kept than the ceiling and the one byte that proved it was passed, however much came.
        assertThat(new String(channels.stdout(), StandardCharsets.UTF_8)).isEqualTo("12345");
    }

    @Test
    void readsANonZeroExitCodeFromTheStatus() {
        ExecChannels channels = new ExecChannels(16);
        channels.accept(message(3, """
                {"status":"Failure","reason":"NonZeroExitCode","message":"command terminated with non-zero exit code",
                 "details":{"causes":[{"reason":"ExitCode","message":"2"}]}}"""), true);

        assertThat(channels.exitCode(json)).contains(2);
    }

    @Test
    void noStatusIsNoExitCode() {
        // A socket that closed without a status reported nothing: an empty answer, never a zero.
        assertThat(new ExecChannels(16).exitCode(json)).isEmpty();
    }

    @Test
    void aCommandThatNeverRanIsAFailureNotAnExitCode() {
        ExecChannels channels = new ExecChannels(16);
        channels.accept(message(3, """
                {"status":"Failure","reason":"InternalError","code":500,
                 "message":"exec: \\"tar\\": executable file not found in $PATH"}"""), true);

        assertThatThrownBy(() -> channels.exitCode(json))
                .isInstanceOf(KubernetesException.class)
                .hasMessageContaining("executable file not found");
    }

    @Test
    void anUnreadableStatusIsAFailure() {
        ExecChannels channels = new ExecChannels(16);
        channels.accept(message(3, "not json"), true);

        assertThatThrownBy(() -> channels.exitCode(json)).isInstanceOf(KubernetesException.class);
    }
}
