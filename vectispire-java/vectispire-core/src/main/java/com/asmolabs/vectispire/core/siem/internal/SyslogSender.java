package com.asmolabs.vectispire.core.siem.internal;

import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.common.domain.siem.SyslogMessage;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.springframework.stereotype.Component;

/**
 * Sends one syslog message to the address that was validated, and to no other.
 *
 * <p>The syslog counterpart of {@link PinnedHttpSender}, and bound by the same rule: it takes a
 * {@link OutboundUrlGuard.Destination} — what the guard resolved and accepted — and connects to
 * those addresses, never to the name. A name resolved a second time here could answer with the
 * metadata endpoint, and the check before it would have decided nothing. {@code ArchitectureTest}
 * keeps it the only class in the control plane that opens a raw socket.
 *
 * <h2>TLS</h2>
 *
 * <p>The TCP connection is opened to the pinned address and TLS is layered on it with the host
 * <em>as written</em>, so SNI and certificate verification are about the name the operator typed —
 * connecting to an IP literal and verifying against it would have broken both. Hostname
 * verification is on ({@code HTTPS} endpoint identification), the protocols are TLS 1.3 and 1.2,
 * and the trust store is the JVM's: a collector with a private CA needs that CA in the JVM's store,
 * which is a deployment step, not a setting — see the SIEM page of the guide.
 *
 * <h2>Timeouts</h2>
 *
 * <p>The connect has one, the TLS handshake reads under {@code SO_TIMEOUT}, and the write — which
 * Java sockets cannot time out — is bounded by a watchdog that closes the socket at the deadline.
 * A collector that accepts a connection and then stops reading would otherwise hold the relay's
 * thread, and with it every other message behind this one.
 *
 * <h2>One connection per message</h2>
 *
 * <p>The relay sends at most twenty messages a minute; a pooled connection would save little, and
 * like the HTTP pool that {@code PinnedHttpSender} refuses it would turn "we checked this
 * destination" into "we checked it once". Recorded as a follow-up if volume ever says otherwise.
 */
@Component
public class SyslogSender {

    /** The largest UDP payload IPv4 can carry. Past it the datagram is not truncated, it is not sent. */
    static final int MAX_DATAGRAM = 65_507;

    private static final List<String> PROTOCOLS = List.of("TLSv1.3", "TLSv1.2");

    /**
     * Closes a socket whose write outlives its deadline. One daemon thread for the process: it only
     * ever runs a {@code close}, and a cancelled task is removed rather than left to pile up.
     */
    private static final ScheduledThreadPoolExecutor WATCHDOG = watchdog();

    private final SSLSocketFactory tls;

    /** The JVM's default TLS context: its trust store, its providers. */
    public SyslogSender() {
        this(defaultTls());
    }

    /**
     * <b>The test seam, and the only one.</b> The real-socket tests stand up a TLS collector with a
     * certificate they generate, which no system trust store holds; they hand in a context that
     * trusts it. Hostname verification, the protocol floor and the pinning are applied by this class
     * whatever the factory, so the seam replaces <em>whom</em> to trust and nothing about
     * <em>how</em>. Package-private, so production wiring cannot reach it.
     */
    SyslogSender(SSLSocketFactory tls) {
        this.tls = tls;
    }

    /**
     * Sends, or throws {@link OutboundJson.OutboundFailureException} — which the outbox turns into
     * a retry.
     *
     * @param protocol one of the three syslog protocols
     * @param destination what the guard checked; its addresses are the only ones connected to
     * @param message an RFC 5424 message, unframed: this method frames it for the transport
     */
    public void send(
            SiemProtocol protocol,
            OutboundUrlGuard.Destination destination,
            int port,
            String message,
            Duration timeout,
            String label) {
        if (destination.addresses().isEmpty()) {
            // Refused rather than sent unpinned, for PinnedHttpSender's reason: with no checked
            // address, the only way to send would be to resolve the name again here.
            throw new OutboundJson.OutboundFailureException(
                    label + ": the host " + destination.host() + " does not resolve, so no checked address exists "
                            + "to send to.");
        }
        switch (protocol) {
            case SYSLOG_UDP -> sendDatagram(destination, port, message, label);
            case SYSLOG_TCP -> sendStream(destination, port, SyslogMessage.octetCounted(message), timeout, false, label);
            case SYSLOG_TLS -> sendStream(destination, port, SyslogMessage.octetCounted(message), timeout, true, label);
            case WEBHOOK -> throw new IllegalArgumentException("A webhook is sent over HTTP, not syslog.");
        }
    }

    /**
     * One datagram, RFC 5426: no framing, the datagram is the message.
     *
     * <p><b>Fire and forget, and that is UDP's contract, not ours.</b> A datagram that is sent is a
     * datagram the network may drop; nothing comes back to say so, and the outbox marks it delivered.
     * The documentation says it: a SOC that needs delivery uses TCP or TLS.
     */
    private static void sendDatagram(OutboundUrlGuard.Destination destination, int port, String message, String label) {
        byte[] payload = message.getBytes(StandardCharsets.UTF_8);
        if (payload.length > MAX_DATAGRAM) {
            throw new OutboundJson.OutboundFailureException(
                    label + ": a " + payload.length + "-byte event does not fit in one UDP datagram.");
        }
        InetAddress address = destination.addresses().getFirst();
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.send(new DatagramPacket(payload, payload.length, address, port));
        } catch (IOException unreachable) {
            throw new OutboundJson.OutboundFailureException(label + ": " + unreachable.getMessage(), unreachable);
        }
    }

    private void sendStream(
            OutboundUrlGuard.Destination destination,
            int port,
            byte[] frame,
            Duration timeout,
            boolean encrypted,
            String label) {
        Socket plain = connect(destination, port, timeout, label);
        int millis = (int) Math.min(Integer.MAX_VALUE, timeout.toMillis());
        ScheduledFuture<?> deadline = WATCHDOG.schedule(() -> closeQuietly(plain), millis, TimeUnit.MILLISECONDS);
        try (Socket socket = encrypted ? handshake(plain, destination.host(), port, millis) : plain) {
            socket.setSoTimeout(millis);
            OutputStream out = socket.getOutputStream();
            out.write(frame);
            out.flush();
            // A half-close tells the collector the stream is complete; a plain close could
            // discard what is still in the send buffer on some stacks.
            if (!encrypted) {
                socket.shutdownOutput();
            }
        } catch (IOException failed) {
            throw new OutboundJson.OutboundFailureException(
                    label + ": " + (deadline.isDone() && !deadline.isCancelled()
                            ? "the collector did not accept the event within " + timeout.toSeconds() + "s"
                            : failed.getMessage()),
                    failed);
        } finally {
            deadline.cancel(false);
            closeQuietly(plain);
        }
    }

    /**
     * The first checked address that accepts, in the order the guard resolved them.
     *
     * <p>Every one of them passed the policy, so trying the next is not a way around the check — it
     * is what a name with an IPv6 and an IPv4 answer needs when one of the two families is down.
     */
    private static Socket connect(OutboundUrlGuard.Destination destination, int port, Duration timeout, String label) {
        IOException last = null;
        for (InetAddress address : destination.addresses()) {
            Socket socket = new Socket();
            try {
                socket.connect(new InetSocketAddress(address, port), (int) Math.min(Integer.MAX_VALUE, timeout.toMillis()));
                return socket;
            } catch (IOException refused) {
                closeQuietly(socket);
                last = refused;
            }
        }
        throw new OutboundJson.OutboundFailureException(
                label + ": " + destination.url() + " is unreachable (" + (last == null ? "no address" : last.getMessage())
                        + ").",
                last);
    }

    /** TLS over the pinned connection, verified against the host as written. */
    private SSLSocket handshake(Socket plain, String host, int port, int timeoutMillis) throws IOException {
        SSLSocket secured = (SSLSocket) tls.createSocket(plain, host, port, true);
        SSLParameters parameters = secured.getSSLParameters();
        // **The line that makes it TLS rather than encryption.** Without an endpoint
        // identification algorithm JSSE checks that the chain is trusted and not that it was issued
        // to this host: any certificate a public CA ever signed, for any name, would be accepted.
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setProtocols(PROTOCOLS.stream()
                .filter(protocol -> Arrays.asList(secured.getSupportedProtocols()).contains(protocol))
                .toArray(String[]::new));
        secured.setSSLParameters(parameters);
        secured.setSoTimeout(timeoutMillis);
        secured.startHandshake();
        return secured;
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // Closing is the cleanup; a failure to close has nobody left to report to.
        }
    }

    private static SSLSocketFactory defaultTls() {
        try {
            return SSLContext.getDefault().getSocketFactory();
        } catch (NoSuchAlgorithmException impossible) {
            // Every JDK ships a default TLS context; not having one is a broken runtime.
            throw new IllegalStateException("No default TLS context in this JVM", impossible);
        }
    }

    private static ScheduledThreadPoolExecutor watchdog() {
        ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, "syslog-write-deadline");
            thread.setDaemon(true);
            return thread;
        });
        executor.setRemoveOnCancelPolicy(true);
        return executor;
    }
}
