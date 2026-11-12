package com.asmolabs.vectispire.core.golden;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.core.util.Separators;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.cfg.JsonNodeFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.Charset;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.opentest4j.TestAbortedException;
import org.springframework.core.env.Environment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultHandler;
import org.springframework.test.web.servlet.setup.ConfigurableMockMvcBuilder;
import org.springframework.web.context.WebApplicationContext;

/**
 * Writes every request the HTTP suites make, with its response and the rows it touched, to golden
 * files — the oracle the Rust control plane replays (port plan §4.3, task 0.5). README.md beside this
 * class is the format.
 *
 * <p><b>Off unless {@value #PROPERTY} names a directory</b>, and off means absent: {@link #wire}
 * returns the builder it was given, untouched, and the extension's callbacks return at their first
 * line. The suite that runs on every build is the suite that ran before this class existed.
 *
 * <p><b>Wired once, in the harness.</b> {@code ApiTestBase} and the two SCIM token classes, the only
 * places that build a {@code MockMvc}, pass their builder through {@link #wire}; {@code
 * VectispireContextTest} carries the {@link Extension} that tells the recorder which test is running.
 * A test file does not know it is being recorded.
 *
 * <p><b>Two hooks, because a {@link ResultHandler} runs after the request.</b> The filter, first in the
 * chain, reads the tables before the request and anything that changed since the previous one — the
 * rows the test seeded itself; the handler, which MockMvc calls with the finished result, reads them
 * after. A request whose chain throws never reaches the handler, so the filter writes that one.
 */
public final class TrafficRecorder {

    /** The system property naming the output directory; Gradle forwards {@code -Pvectispire.golden.dir}. */
    public static final String PROPERTY = "vectispire.golden.dir";

    /** The golden format's version, in every file and the manifest. */
    static final int FORMAT = 1;

    private static final String PENDING = TrafficRecorder.class.getName() + ".pending";

    /** A request body past this is written beside its golden, gzipped ({@code <golden>.body.gz}). */
    static final int SIDECAR_THRESHOLD = 64 * 1024;
    private static final String CORE_PACKAGE = "com.asmolabs.vectispire.core.";

    private static final Optional<Path> OUTPUT = Optional.ofNullable(System.getProperty(PROPERTY))
            .filter(value -> !value.isBlank())
            .map(value -> Path.of(value).toAbsolutePath().normalize());

    /**
     * Response numbers as served: a float is read as a {@code BigDecimal}, so {@code 1.50} stays
     * {@code 1.50}, and fields keep the order the server wrote them in.
     */
    private static final ObjectMapper JSON = JsonMapper.builder()
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .disable(JsonNodeFeature.STRIP_TRAILING_BIGDECIMAL_ZEROES)
            .build();

    private static final ObjectWriter PRETTY = JSON.writer(new DefaultPrettyPrinter()
            .withSeparators(Separators.createDefaultInstance()
                    .withObjectFieldValueSpacing(Separators.Spacing.AFTER))
            .withObjectIndenter(new DefaultIndenter("  ", "\n"))
            .withArrayIndenter(new DefaultIndenter("  ", "\n")));

    private static volatile TestRecording current;
    private static final Map<String, Map<String, TestEntry>> MANIFEST = new ConcurrentHashMap<>();
    private static final List<String> RECORDER_FAILURES = Collections.synchronizedList(new ArrayList<>());
    private static volatile RowSnapshots lastRows;

    static {
        OUTPUT.ifPresent(TrafficRecorder::prepare);
    }

    private TrafficRecorder() {}

    public static boolean enabled() {
        return OUTPUT.isPresent();
    }

    /**
     * Records every request the built {@code MockMvc} performs — when recording; otherwise returns the
     * builder untouched. Call it before {@code addFilters}: the recorder's filter has to be the first,
     * or the security chain's own writes (a session's last sight) land in the seed instead of the effect.
     */
    public static <B extends ConfigurableMockMvcBuilder<B>> B wire(B builder, WebApplicationContext context) {
        if (!enabled()) {
            return builder;
        }
        TestRecording test = current;
        if (test != null) {
            Environment environment = context.getEnvironment();
            RowSnapshots rows = RowSnapshots.of(
                    environment.getRequiredProperty("spring.datasource.url"),
                    environment.getProperty("spring.datasource.username"),
                    environment.getProperty("spring.datasource.password"));
            lastRows = rows;
            test.attach(rows);
        }
        return builder.addFilters(new RecordingFilter()).alwaysDo(new RecordingHandler());
    }

    /** Tells the recorder which test is running. Inert unless recording. */
    public static final class Extension implements BeforeEachCallback, AfterEachCallback {

        @Override
        public void beforeEach(ExtensionContext context) {
            if (!enabled()) {
                return;
            }
            current = new TestRecording(context);
        }

        @Override
        public void afterEach(ExtensionContext context) {
            if (!enabled()) {
                return;
            }
            TestRecording test = current;
            current = null;
            if (test != null) {
                test.finish(context.getExecutionException().map(failure ->
                        failure instanceof TestAbortedException ? "aborted" : "failed").orElse("passed"));
            }
        }
    }

    /** First in the chain: the seed, and the record of a request whose chain threw. */
    private static final class RecordingFilter implements Filter {

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            TestRecording test = current;
            if (test == null || !(request instanceof MockHttpServletRequest mock)) {
                chain.doFilter(request, response);
                return;
            }
            Pending pending = test.begin(mock);
            mock.setAttribute(PENDING, pending);
            try {
                chain.doFilter(request, response);
            } catch (IOException | ServletException | RuntimeException | Error thrown) {
                test.end(pending, mock, (MockHttpServletResponse) response, null, thrown);
                throw thrown;
            }
        }
    }

    /** After the request, with its finished result: everything else. */
    private static final class RecordingHandler implements ResultHandler {

        @Override
        public void handle(MvcResult result) {
            TestRecording test = current;
            if (test == null || !(result.getRequest().getAttribute(PENDING) instanceof Pending pending)) {
                return;
            }
            test.end(pending, result.getRequest(), result.getResponse(), result, null);
        }
    }

    /** A request under way: its number and what the tables held before it. */
    private record Pending(int sequence, String async, RowSnapshots.Snapshot before, JsonNode seed, boolean concurrent) {}

    /** What the manifest says about one test. */
    private record TestEntry(String name, String outcome, List<String> files, JsonNode baseline, List<String> notes) {}

    /** One test's recording. */
    private static final class TestRecording {

        private final String classKey;
        private final String testKey;
        private final String method;
        private final String invocation;
        private final Placeholders placeholders = new Placeholders();
        private final List<String> files = Collections.synchronizedList(new ArrayList<>());
        private final List<String> notes = Collections.synchronizedList(new ArrayList<>());
        private final AtomicInteger sequence = new AtomicInteger();
        private final AtomicInteger inFlight = new AtomicInteger();
        private RowSnapshots rows;
        private RowSnapshots.Snapshot lastState;
        private JsonNode baseline;
        private boolean overlapped;

        TestRecording(ExtensionContext context) {
            Class<?> testClass = context.getRequiredTestClass();
            String binary = testClass.getName();
            this.classKey = (binary.startsWith(CORE_PACKAGE) ? binary.substring(CORE_PACKAGE.length()) : binary)
                    .replace('$', '.');
            this.method = context.getRequiredTestMethod().getName();
            this.invocation = invocationOf(context.getUniqueId());
            this.testKey = invocation == null ? method : method + "#" + invocation;
        }

        /**
         * Called by {@link #wire} once the harness has emptied the tables, before the test seeds a row:
         * where each table's identities start for this test — its ranks count from there — and the
         * baseline. Called again by a class that rebuilds its {@code MockMvc}, which only reads them
         * again if no request was recorded yet.
         */
        synchronized void attach(RowSnapshots rows) {
            if (this.rows != null && sequence.get() > 0) {
                return;
            }
            this.rows = rows;
            rows.placeIdentities().forEach(reason -> RECORDER_FAILURES.add("identity base not set: " + reason));
            Map<String, Long> next = rows.nextIdentities();
            List<Placeholders.IdRange> ranges = new ArrayList<>();
            for (RowSnapshots.Table table : rows.tables()) {
                if (!table.autoIncrement()) {
                    continue;
                }
                long start = next.getOrDefault(table.name(), table.idBase() + 1);
                if (start < table.idBase() || start >= table.idBase() + RowSnapshots.ID_STRIDE) {
                    // Past its million, a table's ids read as the next table's: ranks would lie.
                    notes.add("identities of " + table.name() + " outside their range: next is " + start);
                    RECORDER_FAILURES.add(classKey + "#" + testKey + ": identities of " + table.name()
                            + " outside their range");
                }
                ranges.add(new Placeholders.IdRange(table.name(), table.idBase(), start));
            }
            synchronized (placeholders) {
                placeholders.identities(ranges, RowSnapshots.ID_STRIDE);
            }
            lastState = rows.snapshot();
            baseline = rows.dump(lastState);
        }

        Pending begin(MockHttpServletRequest request) {
            boolean dispatch = request.getDispatcherType() == DispatcherType.ASYNC;
            int number = sequence.incrementAndGet();
            boolean concurrent = inFlight.incrementAndGet() > 1;
            synchronized (this) {
                overlapped |= concurrent;
                if (rows == null || overlapped) {
                    return new Pending(number, dispatch ? "dispatch" : null, null, null, overlapped);
                }
                RowSnapshots.Snapshot before = rows.snapshot();
                JsonNode seed = rows.diff(lastState, before);
                return new Pending(number, dispatch ? "dispatch" : null, before, seed, false);
            }
        }

        void end(Pending pending, MockHttpServletRequest request, MockHttpServletResponse response,
                MvcResult result, Throwable thrown) {
            try {
                JsonNode effect = null;
                boolean concurrent;
                synchronized (this) {
                    concurrent = pending.concurrent() || overlapped;
                    if (!concurrent && rows != null && pending.before() != null) {
                        RowSnapshots.Snapshot after = rows.snapshot();
                        effect = rows.diff(pending.before(), after);
                        lastState = after;
                    }
                }
                write(pending, request, response, result, thrown, effect, concurrent);
            } catch (RuntimeException failed) {
                RECORDER_FAILURES.add(classKey + "#" + testKey + " request " + pending.sequence() + ": " + failed);
                notes.add("request " + pending.sequence() + " not recorded: " + failed);
            } finally {
                if (inFlight.decrementAndGet() == 0) {
                    synchronized (this) {
                        if (overlapped && rows != null) {
                            // Requests overlapped: what each touched cannot be told apart. The next
                            // request alone starts from what the tables hold now.
                            lastState = rows.snapshot();
                            overlapped = false;
                        }
                    }
                }
            }
        }

        private void write(Pending pending, MockHttpServletRequest request, MockHttpServletResponse response,
                MvcResult result, Throwable thrown, JsonNode effect, boolean concurrent) {
            ObjectNode raw = JsonNodeFactory.instance.objectNode();
            raw.set("request", request(request));
            raw.set("seed", pending.seed());
            raw.set("response", response(response, result, thrown));
            raw.set("effect", effect);

            synchronized (placeholders) {
                collectCredentials(raw);
                JsonNode rendered = placeholders.render(raw);
                dropUnchangedUpdates(rendered.get("seed"));
                dropUnchangedUpdates(rendered.get("effect"));

                ObjectNode golden = JsonNodeFactory.instance.objectNode();
                golden.put("format", FORMAT);
                ObjectNode test = golden.putObject("test");
                test.put("class", classKey);
                test.put("method", method);
                if (invocation != null) {
                    test.put("invocation", invocation);
                }
                golden.put("sequence", pending.sequence());
                if (pending.async() != null) {
                    golden.put("async", pending.async());
                } else if (result != null && request.isAsyncStarted()) {
                    golden.put("async", "started");
                }
                if (concurrent) {
                    golden.put("concurrent", true);
                }
                golden.setAll((ObjectNode) rendered);
                if (concurrent) {
                    golden.remove("seed");
                    golden.remove("effect");
                }

                String name = fileName(pending.sequence(), golden.get("request"));
                Path file = OUTPUT.orElseThrow().resolve(directoryOf(classKey)).resolve(name);
                try {
                    Files.createDirectories(file.getParent());
                    if (golden.path("response").path("body").has("file")) {
                        String sidecar = name.substring(0, name.length() - ".json".length()) + ".response.gz";
                        try (var out = new java.util.zip.GZIPOutputStream(Files.newOutputStream(file.resolveSibling(sidecar)))) {
                            out.write(response.getContentAsByteArray());
                        }
                        ((ObjectNode) golden.path("response").path("body")).put("file", sidecar);
                    }
                    if (golden.path("request").path("body").has("file")) {
                        String sidecar = name.substring(0, name.length() - ".json".length()) + ".body.gz";
                        // GZIPOutputStream writes no time and no name: the same bytes give the same file.
                        try (var out = new java.util.zip.GZIPOutputStream(Files.newOutputStream(file.resolveSibling(sidecar)))) {
                            out.write(request.getContentAsByteArray());
                        }
                        ((ObjectNode) golden.path("request").path("body")).put("file", sidecar);
                    }
                    Files.writeString(file, PRETTY.writeValueAsString(golden) + "\n", StandardCharsets.UTF_8);
                } catch (IOException failed) {
                    throw new UncheckedIOException(failed);
                }
                files.add(name);
            }
        }

        private void collectCredentials(JsonNode raw) {
            for (JsonNode header : raw.path("request").path("headers")) {
                String line = header.asText();
                int colon = line.indexOf(": ");
                String headerName = line.substring(0, colon).toLowerCase(Locale.ROOT);
                String value = line.substring(colon + 2);
                switch (headerName) {
                    case "authorization", "proxy-authorization" -> placeholders.collectAuthorization(value);
                    case "cookie" -> Stream.of(value.split(";")).forEach(placeholders::collectCookie);
                    default -> {
                        if (headerName.contains("token") || headerName.contains("secret") || headerName.contains("key")) {
                            placeholders.registerSecret(value);
                        }
                    }
                }
            }
            for (JsonNode cookie : raw.path("request").path("cookies")) {
                placeholders.registerSecret(cookie.get(1).asText());
            }
            for (JsonNode header : raw.path("response").path("headers")) {
                String line = header.asText();
                if (line.regionMatches(true, 0, "Set-Cookie: ", 0, "Set-Cookie: ".length())) {
                    placeholders.collectCookie(line.substring("Set-Cookie: ".length()));
                }
            }
            placeholders.collect(raw, null);
        }

        void finish(String outcome) {
            if (files.isEmpty() && notes.isEmpty()) {
                return;
            }
            List<String> sorted = new ArrayList<>(files);
            sorted.sort(null);
            JsonNode shownBaseline = baseline == null || baseline.isEmpty() ? null : placeholders.render(baseline);
            MANIFEST.computeIfAbsent(classKey, key -> new ConcurrentHashMap<>())
                    .put(testKey, new TestEntry(testKey, outcome, List.copyOf(sorted), shownBaseline, List.copyOf(notes)));
        }

        private String fileName(int number, JsonNode request) {
            String path = request.path("path").asText("");
            String slug = path.replaceAll("^/+", "").replaceAll("[^A-Za-z0-9._-]+", "_");
            if (slug.length() > 80) {
                slug = slug.substring(0, 80);
            }
            return safe(testKey) + "--" + String.format(Locale.ROOT, "%03d", number) + "-"
                    + request.path("method").asText("X") + "-" + slug + ".json";
        }
    }

    /** {@code [test-template-invocation:#3]} — a parameterised or repeated test's index, stable across runs. */
    private static String invocationOf(String uniqueId) {
        int at = uniqueId.lastIndexOf("-invocation:#");
        if (at < 0) {
            return null;
        }
        int end = uniqueId.indexOf(']', at);
        return uniqueId.substring(at + "-invocation:#".length(), end < 0 ? uniqueId.length() : end);
    }

    private static String directoryOf(String classKey) {
        return safe(classKey);
    }

    private static String safe(String name) {
        return name.replaceAll("[^A-Za-z0-9._#-]", "_");
    }

    /**
     * A row updated only in what the placeholders hide — a session's last sight, from one instant to
     * the next — shows as a change from {@code «instant»} to {@code «instant»}. Whether it happens at
     * all depends on how long the previous request took, so it is dropped rather than recorded.
     */
    private static void dropUnchangedUpdates(JsonNode diff) {
        if (diff == null || !diff.isObject()) {
            return;
        }
        List<String> emptyTables = new ArrayList<>();
        diff.properties().forEach(table -> {
            JsonNode updated = table.getValue().get("updated");
            if (updated instanceof ArrayNode updates) {
                for (int i = updates.size() - 1; i >= 0; i--) {
                    ObjectNode changed = (ObjectNode) updates.get(i).get("changed");
                    List<String> same = new ArrayList<>();
                    changed.properties().forEach(column -> {
                        if (column.getValue().get("from").equals(column.getValue().get("to"))) {
                            same.add(column.getKey());
                        }
                    });
                    changed.remove(same);
                    if (changed.isEmpty()) {
                        updates.remove(i);
                    }
                }
                if (updates.isEmpty()) {
                    ((ObjectNode) table.getValue()).remove("updated");
                }
            }
            if (table.getValue().isEmpty()) {
                emptyTables.add(table.getKey());
            }
        });
        ((ObjectNode) diff).remove(emptyTables);
    }

    private static ObjectNode request(MockHttpServletRequest request) {
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        node.put("method", request.getMethod());
        node.put("path", request.getRequestURI());
        if (request.getQueryString() != null) {
            node.put("query", request.getQueryString());
        }
        if (!request.getParameterMap().isEmpty()) {
            ObjectNode params = node.putObject("params");
            request.getParameterMap().forEach((name, values) -> {
                ArrayNode array = params.putArray(name);
                for (String value : values) {
                    array.add(value);
                }
            });
        }
        ArrayNode headers = JsonNodeFactory.instance.arrayNode();
        for (String name : Collections.list(request.getHeaderNames())) {
            if (name.equalsIgnoreCase("Content-Length")) {
                continue;
            }
            for (String value : Collections.list(request.getHeaders(name))) {
                headers.add(name + ": " + value);
            }
        }
        if (!headers.isEmpty()) {
            node.set("headers", headers);
        }
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            ArrayNode array = node.putArray("cookies");
            for (Cookie cookie : cookies) {
                array.addArray().add(cookie.getName()).add(cookie.getValue());
            }
        }
        if (!"127.0.0.1".equals(request.getRemoteAddr())) {
            node.put("remoteAddr", request.getRemoteAddr());
        }
        if (request.isSecure() || !"http".equals(request.getScheme())) {
            node.put("scheme", request.getScheme());
        }
        byte[] content = request.getContentAsByteArray();
        if (content != null && content.length > SIDECAR_THRESHOLD) {
            // The bounds' tests send megabytes of padding, most of the suite's bytes once inline: kept beside
            // the golden, compressed, and sent as they are — no placeholder is applied to them.
            ObjectNode body = node.putObject("body");
            if (request.getContentType() != null) {
                body.put("contentType", request.getContentType());
            }
            body.put("length", content.length);
            body.put("sha256", HexFormat.of().formatHex(Digests.sha256(content)));
            body.putNull("file");
        } else if (content != null && content.length > 0) {
            node.set("body", body(content, request.getContentType(), request.getCharacterEncoding(), true));
        }
        return node;
    }

    private static ObjectNode response(MockHttpServletResponse response, MvcResult result, Throwable thrown) {
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        if (thrown != null) {
            // The chain threw: MockMvc hands the exception to the test, a container would answer 500.
            node.put("thrown", thrown.getClass().getName());
            return node;
        }
        node.put("status", response.getStatus());
        if (response.getErrorMessage() != null) {
            // sendError's reason: MockMvc keeps it, a container drops it on its way to the error page.
            node.put("errorMessage", response.getErrorMessage());
        }
        if (response.getForwardedUrl() != null) {
            node.put("forwardedUrl", response.getForwardedUrl());
        }
        if (response.getRedirectedUrl() != null) {
            node.put("redirectedUrl", response.getRedirectedUrl());
        }
        ArrayNode headers = JsonNodeFactory.instance.arrayNode();
        for (String name : response.getHeaderNames()) {
            for (String value : response.getHeaders(name)) {
                headers.add(name + ": " + value);
            }
        }
        if (!headers.isEmpty()) {
            node.set("headers", headers);
        }
        byte[] content = response.getContentAsByteArray();
        if (content.length > 0) {
            node.set("body", body(content, response.getContentType(), response.getCharacterEncoding(), false));
        }
        return node;
    }

    /**
     * A body as the golden shows it. JSON is parsed — fields in the order served, numbers as served —
     * and a request's is kept as JSON only when writing it back compactly gives its exact bytes, which
     * is what a replay sends: a signed webhook's signature covers the bytes, not the document.
     */
    private static ObjectNode body(byte[] content, String contentType, String encoding, boolean exact) {
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        if (contentType != null) {
            node.put("contentType", contentType);
        }
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        Charset charset = charsetOf(encoding);
        Optional<String> text = decode(content, charset);
        if (text.isPresent() && (type.contains("json") || type.isEmpty() && looksLikeJson(text.get()))) {
            try {
                JsonNode tree = JSON.readTree(text.get());
                if (tree != null && (!exact || JSON.writeValueAsString(tree).equals(text.get()))) {
                    // A request's fields sorted: a test writing Map.of(...) sends them in an order
                    // the JVM draws at start-up, and two recordings would differ on nothing the server did.
                    node.set("json", exact ? sorted(tree) : tree);
                    return node;
                }
            } catch (IOException notJson) {
                // Declared JSON and is not: kept as the text it is, which is what a replay must compare.
            }
        }
        if (text.isPresent() && (isTextual(type) || type.isEmpty())) {
            node.put("text", text.get());
            return node;
        }
        node.put("length", content.length);
        node.put("sha256", HexFormat.of().formatHex(Digests.sha256(content)));
        if (exact) {
            node.put("base64", Base64.getEncoder().encodeToString(content));
        } else {
            // A PDF, an archive, a workbook: kept whole beside the golden, for phase 5's comparisons, which
            // read what a document says rather than its digest. Many embed when they were made.
            node.putNull("file");
        }
        return node;
    }

    private static JsonNode sorted(JsonNode node) {
        if (node.isObject()) {
            ObjectNode copy = JsonNodeFactory.instance.objectNode();
            new TreeMap<>(node.propertyStream().collect(java.util.stream.Collectors.toMap(
                    Map.Entry::getKey, Map.Entry::getValue))).forEach((key, value) -> copy.set(key, sorted(value)));
            return copy;
        }
        if (node.isArray()) {
            ArrayNode copy = JsonNodeFactory.instance.arrayNode();
            node.forEach(element -> copy.add(sorted(element)));
            return copy;
        }
        return node;
    }

    private static boolean looksLikeJson(String text) {
        String trimmed = text.strip();
        return trimmed.startsWith("{") || trimmed.startsWith("[");
    }

    /**
     * Whether a body of this type is kept as text, where {@link Placeholders} can hide what changes at every run.
     *
     * <p><b>PEM is text.</b> {@code application/x-pem-file} — the signing key's public half — was kept as a binary
     * sidecar under its digest: the replay compares no binary answer, and the key, generated at every run, was not
     * hidden, so no other implementation's answer could have matched it. As text, the block is recorded as
     * {@code «pem:public-key:1»}.
     */
    static boolean isTextual(String type) {
        return type.startsWith("text/") || type.contains("json") || type.contains("xml") || type.contains("yaml")
                || type.contains("csv") || type.contains("x-www-form-urlencoded") || type.contains("javascript")
                || type.contains("pem");
    }

    private static Charset charsetOf(String encoding) {
        try {
            return encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding);
        } catch (RuntimeException unknown) {
            return StandardCharsets.UTF_8;
        }
    }

    private static Optional<String> decode(byte[] content, Charset charset) {
        try {
            return Optional.of(charset.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(content))
                    .toString());
        } catch (CharacterCodingException binary) {
            return Optional.empty();
        }
    }

    /**
     * Empties a directory a previous recording wrote, and refuses any other non-empty one: a property
     * pointed at the wrong place must not cost somebody a directory.
     */
    private static void prepare(Path directory) {
        try {
            if (Files.isDirectory(directory)) {
                boolean empty;
                try (Stream<Path> entries = Files.list(directory)) {
                    empty = entries.findAny().isEmpty();
                }
                if (!empty) {
                    if (!Files.isRegularFile(directory.resolve("manifest.json"))) {
                        throw new IllegalStateException(PROPERTY + " names " + directory
                                + ", which is not empty and holds no manifest.json: refusing to write there");
                    }
                    try (Stream<Path> walk = Files.walk(directory)) {
                        for (Path path : walk.sorted(java.util.Comparator.reverseOrder()).toList()) {
                            if (!path.equals(directory)) {
                                Files.delete(path);
                            }
                        }
                    }
                }
            }
            Files.createDirectories(directory);
            // Written now and again at the end, so a run cut short still leaves a directory the next run may empty.
            writeManifest();
        } catch (IOException failed) {
            throw new UncheckedIOException(failed);
        }
        Runtime.getRuntime().addShutdownHook(new Thread(TrafficRecorder::writeManifest, "golden-manifest"));
    }

    /**
     * The index: classes and tests in name order, never in the order they ran, and nothing that
     * changes between two runs of the same tree — so two recordings compare file by file.
     */
    private static synchronized void writeManifest() {
        ObjectNode manifest = JsonNodeFactory.instance.objectNode();
        manifest.put("format", FORMAT);
        manifest.put("idStride", RowSnapshots.ID_STRIDE);
        RowSnapshots rows = lastRows;
        if (rows != null) {
            ObjectNode bases = manifest.putObject("idBases");
            rows.tables().stream().filter(RowSnapshots.Table::autoIncrement)
                    .forEach(table -> bases.put(table.name(), table.idBase()));
        }
        int classCount = 0;
        int testCount = 0;
        int fileCount = 0;
        ArrayNode classes = JsonNodeFactory.instance.arrayNode();
        for (Map.Entry<String, Map<String, TestEntry>> recorded : new TreeMap<>(MANIFEST).entrySet()) {
            ObjectNode entry = classes.addObject();
            entry.put("class", recorded.getKey());
            entry.put("directory", directoryOf(recorded.getKey()));
            ArrayNode tests = entry.putArray("tests");
            classCount++;
            for (TestEntry test : new TreeMap<>(recorded.getValue()).values()) {
                ObjectNode testNode = tests.addObject();
                testNode.put("name", test.name());
                testNode.put("outcome", test.outcome());
                if (test.baseline() != null) {
                    testNode.set("baseline", test.baseline());
                }
                ArrayNode files = testNode.putArray("files");
                test.files().forEach(files::add);
                if (!test.notes().isEmpty()) {
                    ArrayNode notes = testNode.putArray("notes");
                    test.notes().forEach(notes::add);
                }
                testCount++;
                fileCount += test.files().size();
            }
        }
        ObjectNode totals = manifest.putObject("totals");
        totals.put("classes", classCount);
        totals.put("tests", testCount);
        totals.put("requests", fileCount);
        manifest.set("classes", classes);
        if (!RECORDER_FAILURES.isEmpty()) {
            ArrayNode failures = manifest.putArray("recorderFailures");
            new ArrayList<>(RECORDER_FAILURES).stream().sorted().forEach(failures::add);
        }
        try {
            Files.writeString(OUTPUT.orElseThrow().resolve("manifest.json"),
                    PRETTY.writeValueAsString(manifest) + "\n", StandardCharsets.UTF_8);
        } catch (IOException failed) {
            throw new UncheckedIOException(failed);
        }
    }
}
