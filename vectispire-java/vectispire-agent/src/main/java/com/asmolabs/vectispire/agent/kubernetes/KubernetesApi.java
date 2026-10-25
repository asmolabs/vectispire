package com.asmolabs.vectispire.agent.kubernetes;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.net.http.WebSocketHandshakeException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * The five calls the Kubernetes executor makes to the API server, over the JDK's own client
 * (decision 0045): create, read, list and delete a pod, and {@code exec} in one.
 *
 * <p><b>No client library, deliberately.</b> What the agent needs is this narrow, and a general client
 * brings dozens of artifacts to review and pin for it. The cost is the {@code exec} protocol, written and
 * tested here — {@link ExecChannels} carries the part that can be got wrong.
 *
 * <p><b>Redirects are refused</b>, as for the control plane ({@code AgentHttp}): the API server is a fixed
 * address, and following a redirect would carry the service account's token to a host nobody declared.
 * <b>The token is read again on every call</b>: a projected service-account token is rotated by the kubelet
 * while the agent runs, and one read at start expires under it.
 */
public class KubernetesApi {

    /** The one subprotocol spoken: v4 cannot say "standard input is finished", and {@code tar} waits for it. */
    static final String EXEC_PROTOCOL = "v5.channel.k8s.io";

    private static final Path SERVICE_ACCOUNT = Path.of("/var/run/secrets/kubernetes.io/serviceaccount");
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(30);
    private static final int STDIN_CHUNK = 64 * 1024;

    private final URI server;
    private final Supplier<String> token;
    private final ObjectMapper json;
    private final HttpClient client;

    /**
     * @param server the API server's {@code https} address, with no path
     * @param token the bearer token, asked for on every call
     * @param tls trusting the API server's certificate authority, and nothing else
     */
    public KubernetesApi(URI server, Supplier<String> token, SSLContext tls, ObjectMapper json) {
        if (!"https".equals(server.getScheme())) {
            // The token is a credential: it does not travel in the clear, whatever the configuration says.
            throw new IllegalArgumentException("The API server is reached over https, not " + server.getScheme() + ".");
        }
        this.server = server;
        this.token = token;
        this.json = json;
        this.client = HttpClient.newBuilder()
                .sslContext(tls)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    /**
     * The API server of the cluster the agent runs in, as its pod sees it: the address Kubernetes puts in
     * its environment, the token and the authority it mounts.
     */
    public static KubernetesApi inCluster(ObjectMapper json) {
        String host = System.getenv("KUBERNETES_SERVICE_HOST");
        String port = System.getenv("KUBERNETES_SERVICE_PORT");
        if (host == null || host.isBlank() || port == null || port.isBlank()) {
            throw new IllegalStateException("The Kubernetes executor runs in a pod: KUBERNETES_SERVICE_HOST and "
                    + "KUBERNETES_SERVICE_PORT are not set.");
        }
        String authority = host.contains(":") ? "[" + host + "]" : host;
        Path tokenFile = SERVICE_ACCOUNT.resolve("token");
        return new KubernetesApi(URI.create("https://" + authority + ":" + port), () -> read(tokenFile),
                trusting(SERVICE_ACCOUNT.resolve("ca.crt")), json);
    }

    private static String read(Path tokenFile) {
        try {
            return Files.readString(tokenFile).strip();
        } catch (IOException unreadable) {
            throw new KubernetesException("The service account token could not be read: " + unreadable.getMessage(), unreadable);
        }
    }

    /** A TLS context that trusts the certificates of {@code bundle}, a PEM file, and no other authority. */
    public static SSLContext trusting(Path bundle) {
        try (InputStream in = Files.newInputStream(bundle)) {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            int index = 0;
            for (Certificate certificate : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                store.setCertificateEntry("ca-" + index++, certificate);
            }
            if (index == 0) {
                throw new IllegalStateException("No certificate in " + bundle + ".");
            }
            TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trust.getTrustManagers(), null);
            return context;
        } catch (IOException | GeneralSecurityException unusable) {
            throw new IllegalStateException("The API server's authority could not be read from " + bundle + ": "
                    + unusable.getMessage(), unusable);
        }
    }

    /** Creates {@code pod} in {@code namespace} and returns it as the API server stored it. */
    public JsonNode createPod(String namespace, JsonNode pod) {
        return call("POST", podsPath(namespace), pod, 201).orElseThrow();
    }

    /** The pod, or empty when there is none of that name. */
    public Optional<JsonNode> pod(String namespace, String name) {
        return call("GET", podsPath(namespace) + "/" + segment(name), null, 200);
    }

    /** The pods carrying {@code labelSelector}, in Kubernetes' selector syntax. */
    public List<JsonNode> pods(String namespace, String labelSelector) {
        JsonNode list = call("GET", podsPath(namespace) + "?labelSelector=" + query(labelSelector), null, 200).orElseThrow();
        List<JsonNode> items = new ArrayList<>();
        list.path("items").forEach(items::add);
        return items;
    }

    /** Deletes the pod at once, with no grace period: a scanner has nothing to save. An absent pod is not an error. */
    public void deletePod(String namespace, String name) {
        call("DELETE", podsPath(namespace) + "/" + segment(name) + "?gracePeriodSeconds=0", null, 200, 202);
    }

    /** Deletes every pod carrying {@code labelSelector} — what a crash of the agent left behind. */
    public void deletePods(String namespace, String labelSelector) {
        call("DELETE", podsPath(namespace) + "?gracePeriodSeconds=0&labelSelector=" + query(labelSelector), null, 200, 202);
    }

    /**
     * The first {@code limitBytes} of a container's log — a diagnostic, never a report: the kubelet rotates
     * logs, so what is read here may be cut, and nothing parses it (decision 0045 §4).
     */
    public String log(String namespace, String pod, String container, long limitBytes) {
        return callText(podsPath(namespace) + "/" + segment(pod) + "/log?container=" + query(container)
                + "&limitBytes=" + limitBytes);
    }

    /**
     * Runs {@code command} in {@code container} of a running pod, with {@code stdin} as its standard
     * input when given, and returns what it wrote.
     *
     * <p>Standard input is sent and then <em>closed</em> — v5's close signal — so a {@code tar -x} reading
     * it ends. Standard output stops being read past {@code stdoutCeiling}: the result then says
     * {@link ExecResult#overCeiling()} and carries no exit code.
     *
     * @throws KubernetesException when the server refuses the exec, the command cannot start, or the
     *     timeout passes — never a result that would be read as the command's own
     */
    public ExecResult exec(String namespace, String pod, String container, List<String> command,
            InputStream stdin, long stdoutCeiling, Duration timeout) {
        return exec(namespace, pod, container, command, stdin, new ExecChannels(stdoutCeiling), timeout);
    }

    /**
     * As {@link #exec(String, String, String, List, InputStream, long, Duration)}, with standard output
     * written to {@code stdout} as it arrives rather than held: the result's {@code stdout} is then empty.
     */
    public ExecResult exec(String namespace, String pod, String container, List<String> command,
            InputStream stdin, OutputStream stdout, long stdoutCeiling, Duration timeout) {
        return exec(namespace, pod, container, command, stdin, new ExecChannels(stdout, stdoutCeiling), timeout);
    }

    private ExecResult exec(String namespace, String pod, String container, List<String> command,
            InputStream stdin, ExecChannels channels, Duration timeout) {

        long deadline = System.nanoTime() + timeout.toNanos();
        StringBuilder path = new StringBuilder(podsPath(namespace)).append('/').append(segment(pod)).append("/exec?container=")
                .append(query(container)).append("&stdout=true&stderr=true");
        if (stdin != null) {
            path.append("&stdin=true");
        }
        for (String argument : command) {
            path.append("&command=").append(query(argument));
        }
        URI uri = URI.create(server.toString().replaceFirst("^https", "wss") + path);

        ExecListener listener = new ExecListener(channels);
        WebSocket socket;
        try {
            socket = client.newWebSocketBuilder()
                    .header("Authorization", "Bearer " + token.get())
                    .subprotocols(EXEC_PROTOCOL)
                    .connectTimeout(Duration.ofSeconds(15))
                    .buildAsync(uri, listener)
                    .get(remaining(deadline), TimeUnit.MILLISECONDS);
        } catch (ExecutionException failed) {
            if (failed.getCause() instanceof WebSocketHandshakeException refused) {
                HttpResponse<?> response = refused.getResponse();
                throw new KubernetesException("The exec in " + pod + "/" + container + " was refused: HTTP "
                        + response.statusCode() + " " + excerpt(response.body()), response.statusCode());
            }
            throw new KubernetesException("The exec in " + pod + "/" + container + " could not be opened: "
                    + failed.getCause(), failed.getCause());
        } catch (TimeoutException late) {
            throw new KubernetesException("The exec in " + pod + "/" + container + " was not opened within " + timeout + ".", 0);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new KubernetesException("Interrupted while opening an exec.", interrupted);
        }

        try {
            if (!EXEC_PROTOCOL.equals(socket.getSubprotocol())) {
                throw new KubernetesException("The API server does not speak " + EXEC_PROTOCOL + " (it answered \""
                        + socket.getSubprotocol() + "\"): Kubernetes 1.30 or later is required.", 0);
            }
            if (stdin != null) {
                send(socket, stdin, listener, deadline);
            }
            listener.done.get(remaining(deadline), TimeUnit.MILLISECONDS);
        } catch (ExecutionException broken) {
            throw new KubernetesException("The exec in " + pod + "/" + container + " broke: " + broken.getCause(), broken.getCause());
        } catch (TimeoutException late) {
            throw new KubernetesException("The exec in " + pod + "/" + container + " did not end within " + timeout + ".", 0);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new KubernetesException("Interrupted during an exec.", interrupted);
        } finally {
            socket.abort();
        }

        synchronized (channels) {
            if (channels.overCeiling()) {
                return new ExecResult(channels.stdout(), channels.stderr(), -1, true);
            }
            int exitCode = channels.exitCode(json).orElseThrow(() -> new KubernetesException(
                    "The exec in " + pod + "/" + container + " ended with no status: the command's end was not reported.", 0));
            return new ExecResult(channels.stdout(), channels.stderr(), exitCode, false);
        }
    }

    private static void send(WebSocket socket, InputStream stdin, ExecListener listener, long deadline)
            throws ExecutionException, TimeoutException, InterruptedException {
        byte[] chunk = new byte[STDIN_CHUNK];
        try {
            for (int read; (read = stdin.read(chunk)) >= 0; ) {
                if (listener.done.isDone()) {
                    // The command ended before reading everything — its status says why, not this write.
                    return;
                }
                ByteBuffer frame = ByteBuffer.allocate(read + 1).put(ExecChannels.STDIN).put(chunk, 0, read).flip();
                socket.sendBinary(frame, true).get(remaining(deadline), TimeUnit.MILLISECONDS);
            }
        } catch (IOException unreadable) {
            throw new KubernetesException("The standard input could not be read: " + unreadable.getMessage(), unreadable);
        }
        socket.sendBinary(ByteBuffer.wrap(new byte[] {ExecChannels.CLOSE, ExecChannels.STDIN}), true)
                .get(remaining(deadline), TimeUnit.MILLISECONDS);
    }

    /**
     * What a command wrote and how it ended.
     *
     * @param exitCode its exit code, or -1 when {@code overCeiling}
     * @param overCeiling standard output passed the ceiling, and was not read to its end: a failure, never
     *     a report to parse
     */
    public record ExecResult(byte[] stdout, String stderr, int exitCode, boolean overCeiling) {}

    private static final class ExecListener implements WebSocket.Listener {

        private final ExecChannels channels;
        private final CompletableFuture<Void> done = new CompletableFuture<>();

        ExecListener(ExecChannels channels) {
            this.channels = channels;
        }

        @Override
        public void onOpen(WebSocket socket) {
            socket.request(1);
        }

        @Override
        public CompletionStage<?> onBinary(WebSocket socket, ByteBuffer data, boolean last) {
            boolean more;
            try {
                synchronized (channels) {
                    more = channels.accept(data, last);
                }
            } catch (RuntimeException unwritable) {
                // A sink that refused a write: the copy is broken, and said so rather than left half-made.
                done.completeExceptionally(unwritable);
                return null;
            }
            if (more) {
                socket.request(1);
            } else {
                done.complete(null);
            }
            return null;
        }

        @Override
        public CompletionStage<?> onText(WebSocket socket, CharSequence data, boolean last) {
            socket.request(1);
            return null;
        }

        @Override
        public CompletionStage<?> onClose(WebSocket socket, int statusCode, String reason) {
            done.complete(null);
            return null;
        }

        @Override
        public void onError(WebSocket socket, Throwable error) {
            done.completeExceptionally(error);
        }
    }

    private Optional<JsonNode> call(String method, String path, JsonNode body, int... expected) {
        HttpRequest.Builder request = HttpRequest.newBuilder(server.resolve(path))
                .timeout(CALL_TIMEOUT)
                .header("Authorization", "Bearer " + token.get())
                .header("Accept", "application/json");
        if (body != null) {
            request.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(body.toString()));
        } else {
            request.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<String> response;
        try {
            response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException unreachable) {
            throw new KubernetesException("The API server is unreachable: " + unreachable.getMessage(), unreachable);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new KubernetesException("Interrupted while calling the API server.", interrupted);
        }
        int status = response.statusCode();
        for (int accepted : expected) {
            if (status == accepted) {
                return Optional.of(parse(response.body()));
            }
        }
        if (status == 404 && !"POST".equals(method)) {
            return Optional.empty();
        }
        throw new KubernetesException(method + " " + path.replaceFirst("\\?.*", "") + " answered HTTP " + status + ": "
                + excerpt(response.body()), status);
    }

    private String callText(String path) {
        HttpRequest request = HttpRequest.newBuilder(server.resolve(path))
                .timeout(CALL_TIMEOUT)
                .header("Authorization", "Bearer " + token.get())
                .GET()
                .build();
        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new KubernetesException("GET " + path.replaceFirst("\\?.*", "") + " answered HTTP "
                        + response.statusCode() + ": " + excerpt(response.body()), response.statusCode());
            }
            return response.body();
        } catch (IOException unreachable) {
            throw new KubernetesException("The API server is unreachable: " + unreachable.getMessage(), unreachable);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new KubernetesException("Interrupted while calling the API server.", interrupted);
        }
    }

    private JsonNode parse(String text) {
        try {
            return text == null || text.isBlank() ? json.nullNode() : json.readTree(text);
        } catch (IOException notJson) {
            throw new KubernetesException("The API server answered something that is not JSON: " + excerpt(text), 0);
        }
    }

    /** The server's own message when its answer is a Status, otherwise the start of what it said. */
    private String excerpt(Object body) {
        String text = body == null ? "" : body.toString();
        try {
            String message = json.readTree(text).path("message").asText("");
            if (!message.isEmpty()) {
                return message;
            }
        } catch (IOException notJson) {
            // Fall through to the raw text.
        }
        return text.substring(0, Math.min(text.length(), 300));
    }

    private static String podsPath(String namespace) {
        return "/api/v1/namespaces/" + segment(namespace) + "/pods";
    }

    /** A name in a path: Kubernetes names are DNS labels, so anything else is refused rather than escaped. */
    private static String segment(String name) {
        if (name == null || !name.matches("[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?")) {
            throw new IllegalArgumentException("Not a Kubernetes name: \"" + name + "\".");
        }
        return name;
    }

    private static String query(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /** Milliseconds left before {@code deadline}, a {@link System#nanoTime()}: a timeout is a duration, not a moment. */
    private static long remaining(long deadline) {
        return Math.max(1, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()));
    }
}
