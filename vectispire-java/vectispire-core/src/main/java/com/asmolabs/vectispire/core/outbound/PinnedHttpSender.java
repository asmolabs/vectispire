package com.asmolabs.vectispire.core.outbound;

import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpPut;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.util.Timeout;
import org.springframework.stereotype.Component;

/**
 * Sends a request to the address that was validated, and to no other.
 *
 * <p><b>The window this closes.</b> {@link OutboundUrlGuard} resolves a name to decide whether
 * the policy allows it. A client then given the same <em>name</em> resolves it a second time,
 * and between the two lookups the answer can change: a name whose TTL is one second answers
 * with a public address while the settings page is being saved, and with {@code 169.254.169.254}
 * when the request is actually made. Everything about the guard reads correctly and it protects
 * nothing. That is DNS rebinding, and the only place it can be closed is where the socket is
 * opened.
 *
 * <p><b>Why not {@code java.net.http}.</b> Its {@code HttpClient} has no resolver hook — checked
 * against JDK 25, whose {@code Builder} exposes {@code proxy}, {@code sslContext} and
 * {@code localAddress}, and nothing for DNS. The JDK's answer is
 * {@code InetAddressResolverProvider}, which replaces resolution <b>for the whole process</b>:
 * global mutable state in a program that also serves HTTP, and installed by a service file
 * rather than by the code that needs it — the same objection this codebase makes to registering
 * a JCA provider. Apache's client takes a resolver <em>per client</em>, so the pin has the
 * lifetime of one request and reaches nothing else. It was already on the runtime classpath
 * (docker-java's transport uses it); the build now declares it, because depending on something
 * by accident is not depending on it.
 *
 * <p><b>The name still travels.</b> Only the lookup is replaced. The request carries the
 * original host in its URI, so {@code Host}, SNI and certificate verification are unchanged —
 * connecting to a validated IP literal instead would have broken TLS verification, which is a
 * poor trade for closing an SSRF window.
 *
 * <p><b>One client per request, deliberately.</b> A pooled client keyed by host would hand a
 * later request a socket opened for an earlier validation, and "we checked this destination"
 * would quietly become "we checked it once". These calls are a webhook, a ticket and a model
 * review — rare, and none of them in a hot path.
 */
@Component
public class PinnedHttpSender {

    /** A response, reduced to what every caller here actually reads. */
    public record Response(int status, String body) {}

    /**
     * What an answer may weigh when the caller names no ceiling of its own: 4 MiB.
     *
     * <p><b>The body is read by whoever answers.</b> It was read whole — {@code EntityUtils.toString}
     * with no maximum, into a buffer pre-sized from the {@code Content-Length} the server declared —
     * so a webhook receiver, a tracker or a model server, or anybody an administrator was persuaded to
     * point a setting at, could answer with gigabytes and exhaust the control plane's heap. Every answer
     * read here is a small JSON document — a ticket, a model's review, an EPSS score, an end-of-life
     * index — well under one megabyte; four leaves room for the largest without leaving room for harm.
     * A caller reading a catalogue passes its own ceiling.
     */
    public static final long DEFAULT_MAX_BODY_BYTES = 4L * 1024 * 1024;

    /**
     * How much longer than its read timeout a whole exchange may last.
     *
     * <p>The timeout bounds each read, not the exchange: a server sending one byte just inside it,
     * again and again, held the calling thread — a relay worker, a request thread — for as long as it
     * liked. Twice the timeout covers a slow connect followed by a slow answer.
     */
    static final int DEADLINE_IN_TIMEOUTS = 2;

    /**
     * The verbs a caller here has a use for.
     *
     * <p><b>Why more than GET and POST.</b> The sender used to infer the verb from the body — none
     * meant GET, any meant POST — and every ticket closure went out as a POST. ServiceNow's Table
     * API updates a record by PATCH and GitLab's issue API by PUT; neither routes a POST on a
     * record, so "close the ticket" failed on both trackers, every time, logged at warn by a sweep
     * that retries it forever.
     */
    public enum Method {
        GET, POST, PUT, PATCH
    }

    /**
     * Sends, and returns the status with the body.
     *
     * @param destination what the guard checked, addresses included
     * @param body {@code null} for a GET
     * @throws OutboundJson.OutboundFailureException on anything that is not an answer
     */
    public Response send(
            OutboundUrlGuard.Destination destination,
            Map<String, String> headers,
            String body,
            Duration timeout,
            String label) {
        return send(body == null ? Method.GET : Method.POST, destination, headers, body, timeout, label);
    }

    /**
     * Sends with an explicit verb, reading at most {@link #DEFAULT_MAX_BODY_BYTES} of the answer.
     *
     * @param body {@code null} for none; ignored for a GET, which carries none
     */
    public Response send(
            Method method,
            OutboundUrlGuard.Destination destination,
            Map<String, String> headers,
            String body,
            Duration timeout,
            String label) {
        return send(method, destination, headers, body, timeout, label, DEFAULT_MAX_BODY_BYTES);
    }

    /**
     * Sends with an explicit verb and a ceiling on the answer.
     *
     * @param maxBodyBytes an answer longer than this fails the call, and is not read further
     * @throws OutboundJson.OutboundFailureException on anything that is not an answer, on an answer
     *     past the ceiling, and on an exchange that outlasts {@value #DEADLINE_IN_TIMEOUTS} timeouts
     */
    public Response send(
            Method method,
            OutboundUrlGuard.Destination destination,
            Map<String, String> headers,
            String body,
            Duration timeout,
            String label,
            long maxBodyBytes) {

        if (destination.addresses().isEmpty()) {
            // **Refused rather than sent unpinned.** The guard tolerates a name it could not
            // resolve — for a "is this public?" check the request would fail anyway, so failing
            // the settings screen on a DNS hiccup would be worse. Here it cannot be tolerated:
            // with no address to pin to, the client would resolve the name itself and the check
            // above would have decided nothing. The request fails either way; this way it says
            // why.
            throw new OutboundJson.OutboundFailureException(
                    label + ": the host " + destination.host() + " does not resolve, so no checked address exists "
                            + "to send to.");
        }

        HttpUriRequestBase request = switch (method) {
            case GET -> new HttpGet(destination.url());
            case POST -> new HttpPost(destination.url());
            case PUT -> new HttpPut(destination.url());
            case PATCH -> new HttpPatch(destination.url());
        };
        headers.forEach(request::addHeader);
        if (body != null && method != Method.GET) {
            request.setEntity(new StringEntity(body, ContentType.APPLICATION_JSON));
        }

        Duration deadline = timeout.multipliedBy(DEADLINE_IN_TIMEOUTS);
        AtomicBoolean pastDeadline = new AtomicBoolean();
        // Cancelling the request closes its connection, which ends a read blocked on it. Run on the
        // scheduler's own thread: it only closes a socket.
        CompletableFuture<Void> abort = CompletableFuture.runAsync(() -> {
            pastDeadline.set(true);
            request.cancel();
        }, CompletableFuture.delayedExecutor(deadline.toMillis(), TimeUnit.MILLISECONDS, Runnable::run));
        try (CloseableHttpClient client = pinnedTo(destination, timeout)) {
            return client.execute(request, response -> new Response(
                    response.getCode(), bounded(response.getEntity(), maxBodyBytes, request::cancel, label)));
        } catch (UnknownHostException pinRefused) {
            // The resolver below throws this for a host it was not pinned to, which is what a
            // redirect chased despite the setting, or a rewritten URI, would look like from here.
            throw new OutboundJson.OutboundFailureException(
                    label + ": the request tried to reach a host that was never checked (" + pinRefused.getMessage()
                            + ").",
                    pinRefused);
        } catch (IOException unreachable) {
            if (pastDeadline.get()) {
                throw new OutboundJson.OutboundFailureException(
                        label + ": no complete answer within " + deadline.toSeconds() + " s; the request was abandoned.",
                        unreachable);
            }
            throw new OutboundJson.OutboundFailureException(label + ": " + unreachable.getMessage(), unreachable);
        } finally {
            abort.cancel(false);
        }
    }

    /**
     * The body as text, read up to {@code maxBytes} and no further.
     *
     * <p>Nothing is sized from what the server declares: a {@code Content-Length} is a claim, and the
     * buffer grows with what actually arrives. Decompressed bytes are what is counted, so a small
     * compressed answer that inflates past the ceiling is refused like a large one.
     */
    private static String bounded(HttpEntity entity, long maxBytes, Runnable abort, String label) throws IOException {
        if (entity == null) {
            return "";
        }
        try (InputStream in = entity.getContent()) {
            if (in == null) {
                return "";
            }
            byte[] bytes = in.readNBytes((int) Math.min(Integer.MAX_VALUE - 16, maxBytes + 1));
            if (bytes.length > maxBytes) {
                // Aborted before the stream is closed: closing a response stream drains it so that
                // the connection can be reused — reading the rest of the answer after all, which a
                // test measured at the full quarter gigabyte a server offered.
                abort.run();
                throw new OutboundJson.OutboundFailureException(
                        label + ": the answer is larger than " + maxBytes + " bytes and was not read further.");
            }
            ContentType type = ContentType.parseLenient(entity.getContentType());
            Charset charset = type != null && type.getCharset() != null ? type.getCharset() : StandardCharsets.UTF_8;
            return new String(bytes, charset);
        }
    }

    private static CloseableHttpClient pinnedTo(OutboundUrlGuard.Destination destination, Duration timeout) {
        PoolingHttpClientConnectionManager connections = PoolingHttpClientConnectionManagerBuilder.create()
                .setDnsResolver(pin(destination.host(), destination.addresses()))
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(Timeout.of(timeout))
                        .build())
                .build();

        return HttpClients.custom()
                .setConnectionManager(connections)
                // **Redirects refused, not followed.** A guard that validates a URL and then
                // follows a 302 has validated nothing — the destination checked is not the
                // destination reached. The pin would catch it anyway, by refusing to resolve the
                // new host; both are kept because a defence that only works by accident is one
                // nobody may rely on.
                .disableRedirectHandling()
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setResponseTimeout(Timeout.of(timeout))
                        .setConnectionRequestTimeout(Timeout.of(timeout))
                        .build())
                .build();
    }

    /**
     * A resolver that knows one name and refuses every other.
     *
     * <p>Refusing is the point: it is not a fallback to the system resolver. If anything in the
     * request path asks for a host that was not checked — a redirect somebody re-enabled, a
     * rewritten URI, a proxy setting — the lookup fails instead of quietly succeeding.
     */
    private static DnsResolver pin(String host, List<InetAddress> addresses) {
        InetAddress[] pinned = addresses.toArray(InetAddress[]::new);
        return new DnsResolver() {

            @Override
            public InetAddress[] resolve(String requested) throws UnknownHostException {
                if (!host.equalsIgnoreCase(requested)) {
                    throw new UnknownHostException(requested + " was not the checked host (" + host + ")");
                }
                return pinned;
            }

            @Override
            public String resolveCanonicalHostname(String requested) throws UnknownHostException {
                // The canonical name is used for logging and for Kerberos, neither of which is
                // in play — and a reverse lookup here would be a second question asked of DNS,
                // which is exactly what this class exists to avoid.
                if (!host.equalsIgnoreCase(requested)) {
                    throw new UnknownHostException(requested + " was not the checked host (" + host + ")");
                }
                return host.toLowerCase(Locale.ROOT);
            }
        };
    }
}
