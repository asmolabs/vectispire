package com.asmolabs.vectispire.agent.kubernetes;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * What the API server sends back on an {@code exec} WebSocket, sorted by channel — the part of the
 * {@code v5.channel.k8s.io} protocol that is ours to get right, kept apart from the socket so it is tested
 * without one.
 *
 * <p>Every message starts with one byte naming its channel: 1 standard output, 2 standard error, 3 the
 * status the server writes once the command has ended. <b>Only the first fragment of a message carries
 * it</b>: the JDK hands a large message over in pieces, and reading the first byte of every piece as a
 * channel would scatter a report across stderr and the status.
 *
 * <p><b>Standard output has a ceiling, and passing it is said, never hidden.</b> What is read is a
 * scanner's report; a report cut at the ceiling and parsed leniently is the absent-versus-empty defect
 * (decision 0007), so the caller is told {@link #overCeiling()} and fails the step. Standard error is a
 * diagnostic, kept to its first {@link #STDERR_BYTES} and no more.
 */
final class ExecChannels {

    static final byte STDIN = 0;
    static final byte STDOUT = 1;
    static final byte STDERR = 2;
    static final byte STATUS = 3;
    /** v5's signal: the next byte names a channel the client has finished writing to. */
    static final byte CLOSE = (byte) 255;

    static final int STDERR_BYTES = 64 * 1024;
    /** A status is a small JSON document; one past this is not one. */
    private static final int STATUS_BYTES = 64 * 1024;

    private final long stdoutCeiling;
    private final OutputStream stdout;
    private long stdoutBytes;
    private final ByteArrayOutputStream stderr = new ByteArrayOutputStream();
    private final ByteArrayOutputStream status = new ByteArrayOutputStream();
    private boolean atMessageStart = true;
    private int channel = -1;
    private boolean overCeiling;

    /** Standard output kept in memory, for {@link #stdout()}. */
    ExecChannels(long stdoutCeiling) {
        this(new ByteArrayOutputStream(), stdoutCeiling);
    }

    /**
     * Standard output written to {@code sink} as it comes — a tree copied back is too large to hold — and
     * never more than the ceiling and the one byte that proves it was passed.
     */
    ExecChannels(OutputStream sink, long stdoutCeiling) {
        if (stdoutCeiling < 0) {
            throw new IllegalArgumentException("A ceiling is not negative.");
        }
        this.stdout = sink;
        this.stdoutCeiling = stdoutCeiling;
    }

    /**
     * One fragment of a message, as the socket delivered it.
     *
     * @return false once standard output has passed its ceiling: the caller stops reading
     */
    boolean accept(ByteBuffer fragment, boolean last) {
        if (atMessageStart && fragment.hasRemaining()) {
            channel = fragment.get() & 0xff;
            atMessageStart = false;
        }
        switch (channel) {
            case STDOUT -> stdoutBytes += write(stdout, fragment, stdoutCeiling + 1 - stdoutBytes);
            case STDERR -> append(stderr, fragment, STDERR_BYTES);
            case STATUS -> append(status, fragment, STATUS_BYTES);
            default -> fragment.position(fragment.limit()); // a channel this client never asked for
        }
        if (last) {
            atMessageStart = true;
            channel = -1;
        }
        if (stdoutBytes > stdoutCeiling) {
            overCeiling = true;
        }
        return !overCeiling;
    }

    private static int write(OutputStream to, ByteBuffer fragment, long room) {
        int count = (int) Math.max(0, Math.min(fragment.remaining(), room));
        byte[] bytes = new byte[count];
        fragment.get(bytes);
        try {
            to.write(bytes);
        } catch (IOException unwritable) {
            throw new UncheckedIOException(unwritable);
        }
        fragment.position(fragment.limit());
        return count;
    }

    private static void append(ByteArrayOutputStream to, ByteBuffer fragment, long limit) {
        int room = (int) Math.max(0, Math.min(fragment.remaining(), limit - to.size()));
        byte[] bytes = new byte[room];
        fragment.get(bytes);
        to.write(bytes, 0, room);
        fragment.position(fragment.limit());
    }

    boolean overCeiling() {
        return overCeiling;
    }

    /** What standard output held, when it was kept in memory; empty when it went to a sink. */
    byte[] stdout() {
        return stdout instanceof ByteArrayOutputStream memory ? memory.toByteArray() : new byte[0];
    }

    String stderr() {
        return stderr.toString(StandardCharsets.UTF_8);
    }

    /**
     * The command's exit code, from the status channel — or empty when the server sent no status, which
     * means the command's end was never reported and nothing about it can be believed.
     *
     * @throws KubernetesException when the status says the command did not run at all: a container that
     *     does not exist, a binary that is not in the image
     */
    Optional<Integer> exitCode(ObjectMapper json) {
        if (status.size() == 0) {
            return Optional.empty();
        }
        JsonNode document;
        try {
            document = json.readTree(status.toByteArray());
        } catch (IOException unreadable) {
            throw new KubernetesException("The exec status was not a status document.", 0);
        }
        if ("Success".equals(document.path("status").asText())) {
            return Optional.of(0);
        }
        if ("NonZeroExitCode".equals(document.path("reason").asText())) {
            for (JsonNode cause : document.path("details").path("causes")) {
                if ("ExitCode".equals(cause.path("reason").asText())) {
                    try {
                        return Optional.of(Integer.parseInt(cause.path("message").asText()));
                    } catch (NumberFormatException notACode) {
                        break;
                    }
                }
            }
        }
        throw new KubernetesException("The command did not run: " + document.path("message").asText("no message"),
                document.path("code").asInt(0));
    }
}
