package com.asmolabs.vectispire.core.siem;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.net.UnsafeUrlException;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.siem.SiemEndpoint;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.core.RustReference;
import com.asmolabs.vectispire.core.audit.AuditChainBroken;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPost;
import com.asmolabs.vectispire.core.outbox.GoneDestinationException;
import com.asmolabs.vectispire.core.outbox.OutboxService;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageEntity;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.settings.ProductVersion;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.internal.SiemSender;
import com.asmolabs.vectispire.core.siem.internal.SyslogSender;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigRepository;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.Invocation;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;

/**
 * What the SIEM module writes and sends — the Rust control plane's {@code cp-siem} is held to it
 * ({@code vectispire-rust/reference/siem/module.json}).
 *
 * <p>{@code siem/java-answers.json} pins the domain (the CEF line, the syslog frame, the endpoint, the CA). This pins
 * what the module does with them, byte for byte where bytes leave: <b>the payload an audit entry queues</b>, through
 * the real {@link SiemEvents} and the real {@link OutboxService} over a mocked repository; <b>what a queued payload
 * becomes at delivery</b>, through the real {@link SiemDelivery} and {@link SiemSender} over a mocked
 * {@link OutboundPost} and {@link SyslogSender} — the webhook's JSON body and headers, the syslog message, or the
 * refusal and whether it abandons the row; <b>what a save does</b>, through the real {@link SiemExporterService} over
 * a repository held in memory — the refusal's sentence, the row written, the audit entry's description, the stop
 * notice; and <b>what the connection test answers</b>.
 *
 * <p>Run, never restated: each answer is what the class returned or handed its collaborator. The message id and the
 * instant are fixed, so nothing here is random. A syslog message carries the host's name, which the sender reads from
 * the environment: it is written with that name replaced by {@code {hostname}}.
 */
class SiemModuleReferenceSetTest {

    private static final Instant NOW = Instant.ofEpochSecond(1_790_856_000L, 123_456_000L);
    /**
     * {@code CoreConfiguration.objectMapper()}'s settings, which the outbox and the delivery are handed: an unknown member
     * — the {@code message_id} the outbox stamps into every payload — is ignored, not refused. A plain mapper refuses it,
     * and every row would read as unreadable.
     */
    private static final ObjectMapper JSON = JsonMapper.builder()
            .addModule(new JavaTimeModule())
            .addModule(new Jdk8Module())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();
    private static final UUID MESSAGE_ID = UUID.fromString("0b7e5f0e-6a7c-4f39-9d55-1f3c2a9b8e41");
    private static final String VERSION = "2.3.0";
    private static final String ID_TOKEN = "{message_id}";

    @Test
    void theModuleTheRustSiemIsHeldTo() throws Exception {
        ObjectNode out = RustReference.object();
        out.put("now", NOW.toString());
        out.put("messageId", MESSAGE_ID.toString());
        out.put("version", VERSION);
        out.put("type", SiemEvents.TYPE);
        out.put("authHeaderContext", SiemExporterService.AUTH_HEADER_CONTEXT);
        out.put("refusedByPolicy", SiemExporterService.REFUSED_BY_POLICY);
        out.put("notDelivered", SiemExporterService.NOT_DELIVERED);
        queued(out.putArray("queued"));
        delivered(out.putArray("delivered"));
        saves(out.putArray("saves"));
        tests(out.putArray("tests"));
        RustReference.expect("siem/module.json", out, SiemModuleReferenceSetTest.class);
    }

    // ---- what an audit entry, or a broken chain, queues ----

    private record Entry(
            String name, String minSeverity, AuditOperation operation, String resourceId, String description,
            String user, String ip, String userAgent, SecurityEventType signal) {}

    private static void queued(ArrayNode out) {
        String long1100 = "x".repeat(1_100);
        String splitsAPair = "y".repeat(1_023) + "😀" + "z";
        List<Entry> entries = List.of(
                new Entry("an operation that signals on its own", "LOW", AuditOperation.API_KEY_CREATED, "42",
                        "API key issued: ci-pipeline", "alice", "203.0.113.7", "curl/8.9", null),
                new Entry("a signal its writer named", "LOW", AuditOperation.LOGIN_BLOCKED, "bob",
                        "Sign-in refused: too many failures", "bob", "198.51.100.2", null,
                        SecurityEventType.SIGN_IN_THROTTLED),
                new Entry("an operation that signals nothing", "LOW", AuditOperation.SETTING_UPDATED, "branch",
                        "Branch changed", "alice", null, null, null),
                new Entry("below the minimum", "CRITICAL", AuditOperation.API_KEY_CREATED, "42", "API key issued",
                        "alice", null, null, null),
                new Entry("the minimum, in lower case", "high", AuditOperation.API_KEY_CREATED, "42", "API key issued",
                        "alice", null, null, null),
                new Entry("an unreadable minimum sends everything", "SEVERE", AuditOperation.API_KEY_CREATED, "42",
                        "API key issued", "alice", null, null, null),
                new Entry("a description past 1024 units", "LOW", AuditOperation.API_KEY_CREATED, "42", long1100,
                        "alice", null, null, null),
                new Entry("a cut through a surrogate pair", "LOW", AuditOperation.API_KEY_CREATED, "42", splitsAPair,
                        "alice", null, null, null),
                new Entry("no description, no resource, blank actor", "LOW", AuditOperation.API_KEY_DELETED, null, null,
                        " ", "", "\t", null),
                new Entry("text JSON escapes", "LOW", AuditOperation.API_KEY_CREATED, "q\"uote\\",
                        "line\nbreak\ttab \u0001 é – ✓ 😀   / \u007f", "a\"b", null, "Mozilla/5.0 (X11)", null),
                new Entry("the connection test is never queued", "LOW", AuditOperation.SETTING_UPDATED, "1", "ping",
                        "alice", null, null, SecurityEventType.PING_TEST),
                new Entry("the stop notice is never queued", "LOW", AuditOperation.SETTING_UPDATED, "1", "stop",
                        "alice", null, null, SecurityEventType.SIEM_EXPORT_STOPPED),
                new Entry("a setting change named by its writer", "HIGH", AuditOperation.SETTING_UPDATED, "1",
                        "SIEM configuration updated (enabled=true, protocol=WEBHOOK, minimum severity=HIGH)", "admin",
                        "10.0.0.1", "ua", SecurityEventType.SECURITY_SETTING_CHANGED));
        for (Entry entry : entries) {
            ObjectNode row = out.addObject().put("name", entry.name()).put("minSeverity", entry.minSeverity());
            row.putObject("record")
                    .put("operation", entry.operation().wireName())
                    .put("resourceId", entry.resourceId())
                    .put("description", entry.description())
                    .put("user", entry.user())
                    .put("ip", entry.ip())
                    .put("userAgent", entry.userAgent())
                    .put("signal", entry.signal() == null ? null : entry.signal().name());
            List<String> payloads = queue(entry.minSeverity(), events -> events.recordedInTransaction(
                    new AuditLogService.Record(entry.operation(), entry.resourceId(), entry.description(), entry.user(),
                            entry.ip(), entry.userAgent(), entry.signal()),
                    NOW));
            row.put("payload", payloads.isEmpty() ? null : payloads.getFirst());
        }
        for (AuditChainBroken broken : List.of(new AuditChainBroken("6f1c-entry", 0), new AuditChainBroken(null, 1),
                new AuditChainBroken(null, 3))) {
            ObjectNode row = out.addObject().put("name", "chain broken: " + broken.describe()).put("minSeverity", "HIGH");
            row.putObject("chainBroken").put("brokenAt", broken.brokenAt()).put("missingFromTable",
                    broken.missingFromTable());
            List<String> payloads = queue("HIGH", events -> events.auditChainBroken(broken));
            row.put("payload", payloads.isEmpty() ? null : payloads.getFirst());
        }
    }

    /** The payloads the outbox saved while {@code action} ran, the message id as a token, as the driver stores them. */
    private static List<String> queue(String minSeverity, Consumer<SiemEvents> action) {
        OutboxMessageRepository messages = mock(OutboxMessageRepository.class);
        when(messages.save(any())).thenAnswer(call -> call.getArgument(0));
        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        OutboxService outbox = new OutboxService(messages, List.of(), List.of(), JSON, clock,
                new org.springframework.transaction.support.TransactionTemplate(manager));
        SiemConfigRepository configs = mock(SiemConfigRepository.class);
        SiemConfigEntity config = new SiemConfigEntity();
        config.setEnabled(true);
        config.setProtocol("SYSLOG_UDP");
        config.setEndpoint("127.0.0.1:514");
        config.setMinSeverity(minSeverity);
        when(configs.findById(SiemConfigEntity.SINGLETON_ID)).thenReturn(Optional.of(config));

        action.accept(new SiemEvents(configs, outbox, manager, clock));

        List<String> payloads = new ArrayList<>();
        for (Invocation call : mockingDetails(messages).getInvocations()) {
            if (call.getMethod().getName().equals("save")) {
                OutboxMessageEntity saved = call.getArgument(0);
                payloads.add(stored(saved.getPayload().replace(saved.getId().toString(), ID_TOKEN)));
            }
        }
        return payloads;
    }

    // ---- what a queued payload becomes at delivery ----

    private record Stored(String name, String protocol, String endpoint, boolean enabled, String header, String ca,
            String payload) {}

    private static void delivered(ArrayNode out) throws Exception {
        String root = fixture("01-root.pem");
        String expired = fixture("05-expired.pem");
        String event = "{\"eventType\":\"API_KEY_ISSUED\",\"timestamp\":1790856000123,\"message\":\"API key issued\","
                + "\"extensions\":{\"suser\":\"alice\",\"act\":\"API_KEY_CREATED\"},\"cefSeverity\":5,"
                + "\"message_id\":\"" + MESSAGE_ID + "\"}";
        String webhook = "https://collector.example/cef";
        List<Stored> cases = new ArrayList<>(List.of(
                new Stored("webhook with a header", "WEBHOOK", webhook, true, "Bearer siem-token", null, event),
                new Stored("webhook without a header", "WEBHOOK", webhook, true, null, null, event),
                new Stored("webhook, protocol in lower case", " webhook ", webhook, true, null, null, event),
                new Stored("syslog over UDP", "SYSLOG_UDP", "127.0.0.1:514", true, "Bearer never-sent", null, event),
                new Stored("syslog over TCP", "SYSLOG_TCP", "collector.example:6514", true, null, null, event),
                new Stored("syslog over TLS, a CA pinned", "SYSLOG_TLS", "collector.example:6514", true, null, root,
                        event),
                new Stored("syslog over TLS, no CA", "SYSLOG_TLS", "collector.example:6514", true, null, "  ", event),
                new Stored("a CA stored for a webhook is not read", "WEBHOOK", webhook, true, null, "not a pem", event),
                new Stored("switched off", "WEBHOOK", webhook, false, null, null, event),
                new Stored("no endpoint", "WEBHOOK", null, true, null, null, event),
                new Stored("a blank endpoint", "WEBHOOK", " \t", true, null, null, event),
                new Stored("a protocol this version does not speak", "SMTP", webhook, true, null, null, event),
                new Stored("an endpoint unusable for its protocol", "SYSLOG_TCP", webhook, true, null, null, event),
                new Stored("a CA that has expired since", "SYSLOG_TLS", "collector.example:6514", true, null, expired,
                        event),
                new Stored("an unreadable CA", "SYSLOG_TLS", "collector.example:6514", true, null, "not a pem", event),
                new Stored("the CA is read after the event", "SYSLOG_TLS", "collector.example:6514", true, null,
                        "not a pem", "{\"eventType\":\"NOT_A_TYPE\",\"timestamp\":1}"),
                new Stored("a row queued before the severity was stored", "WEBHOOK", webhook, true, null, null,
                        "{\"eventType\":\"CRITICAL_KEV_DETECTED\",\"timestamp\":1790856000000,\"message\":null,"
                                + "\"extensions\":{\"cs3Label\":\"Identifier\",\"cs3\":\"CVE-2026-0001\"},"
                                + "\"message_id\":\"x\"}"),
                new Stored("an externalId already there keeps its place", "WEBHOOK", webhook, true, null, null,
                        "{\"eventType\":\"API_KEY_REVOKED\",\"timestamp\":0,\"message\":\"m\","
                                + "\"extensions\":{\"externalId\":\"old\",\"suser\":\"bob\"},\"cefSeverity\":4}"),
                new Stored("no extensions", "WEBHOOK", webhook, true, null, null,
                        "{\"eventType\":\"API_KEY_REVOKED\",\"timestamp\":-1,\"message\":\"\",\"extensions\":null}"),
                new Stored("members in another order, one unknown", "WEBHOOK", webhook, true, null, null,
                        "{\"cefSeverity\":8,\"extensions\":{\"act\":\"X\"},\"unknown\":[1,{\"a\":2}],"
                                + "\"message\":\"q\\\"uote \\\\ é \\u2028 😀\",\"timestamp\":1790856000999,"
                                + "\"eventType\":\"AGENT_RESULT_REFUSED\"}"),
                new Stored("an unknown event type", "WEBHOOK", webhook, true, null, null,
                        "{\"eventType\":\"NOT_A_TYPE\",\"timestamp\":1}"),
                new Stored("no event type", "WEBHOOK", webhook, true, null, null, "{\"timestamp\":1}"),
                new Stored("a severity off the scale", "WEBHOOK", webhook, true, null, null,
                        "{\"eventType\":\"API_KEY_ISSUED\",\"timestamp\":1,\"cefSeverity\":11}"),
                new Stored("an extension key that is not one", "WEBHOOK", webhook, true, null, null,
                        "{\"eventType\":\"API_KEY_ISSUED\",\"timestamp\":1,\"extensions\":{\"bad-key\":\"v\"}}"),
                new Stored("not JSON", "WEBHOOK", webhook, true, null, null, "{\"eventType\":")));
        for (Stored input : cases) {
            ObjectNode row = out.addObject().put("name", input.name());
            row.putObject("config")
                    .put("enabled", input.enabled())
                    .put("protocol", input.protocol())
                    .put("endpoint", input.endpoint())
                    .put("header", input.header())
                    .put("ca", input.ca());
            row.put("payload", input.payload());
            deliver(input, row.putObject("answer"));
        }
    }

    private static void deliver(Stored input, ObjectNode answer) throws Exception {
        SiemConfigRepository configs = mock(SiemConfigRepository.class);
        SiemConfigEntity config = new SiemConfigEntity();
        config.setEnabled(input.enabled());
        config.setProtocol(input.protocol());
        config.setEndpoint(input.endpoint());
        config.setAuthHeader(input.header() == null ? null : "v2:" + input.header());
        config.setTlsCaPem(input.ca());
        when(configs.findById(SiemConfigEntity.SINGLETON_ID)).thenReturn(Optional.of(config));
        EncryptionService encryption = mock(EncryptionService.class);
        when(encryption.readSecret(any(), eq(SiemExporterService.AUTH_HEADER_CONTEXT), anyString())).thenAnswer(call -> {
            String stored = call.getArgument(0);
            return stored == null ? "" : stored.substring(3);
        });

        OutboundPost post = mock(OutboundPost.class);
        SyslogSender syslog = mock(SyslogSender.class);
        OutboundUrlGuard guard = mock(OutboundUrlGuard.class);
        when(guard.validateAndResolveEndpoint(anyString(), anyInt(), any(), anyString())).thenAnswer(call ->
                new OutboundUrlGuard.Destination(call.getArgument(0) + ":" + call.getArgument(1), call.getArgument(0),
                        List.of(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}))));
        SettingsService settings = mock(SettingsService.class);
        when(settings.isEnabled(Setting.SIEM_ALLOW_PRIVATE_DESTINATION)).thenReturn(true);
        ProductVersion version = mock(ProductVersion.class);
        when(version.get()).thenReturn(VERSION);
        SiemSender sender = new SiemSender(post, guard, syslog, settings, version);
        SiemDelivery delivery = new SiemDelivery(configs, sender, encryption, JSON, Clock.fixed(NOW, ZoneOffset.UTC));

        try {
            delivery.deliver(MESSAGE_ID, input.payload());
        } catch (GoneDestinationException gone) {
            answer.put("gone", gone.getMessage());
            return;
        } catch (RuntimeException failed) {
            answer.put("kind", failed.getClass().getSimpleName());
            // Jackson's own sentence is not ported: the Rust reader says what it could not read in its words.
            answer.put("message", failed.getMessage().startsWith("A queued SIEM event could not be read: ")
                    ? "A queued SIEM event could not be read: {jackson}"
                    : failed.getMessage());
            return;
        }
        for (Invocation call : mockingDetails(post).getInvocations()) {
            ObjectNode webhook = answer.putObject("webhook");
            webhook.put("url", (String) call.getArgument(0));
            webhook.put("body", JSON.writeValueAsString(call.getArgument(1)));
            webhook.put("policy", ((OutboundPolicy) call.getArgument(2)).name());
            webhook.put("label", (String) call.getArgument(3));
            webhook.set("headers", JSON.valueToTree(call.getArgument(4)));
            webhook.put("timeoutSeconds", ((Duration) call.getArgument(5)).toSeconds());
        }
        for (Invocation call : mockingDetails(guard).getInvocations()) {
            answer.putObject("guard")
                    .put("host", (String) call.getArgument(0))
                    .put("port", (int) call.getArgument(1))
                    .put("policy", ((OutboundPolicy) call.getArgument(2)).name())
                    .put("label", (String) call.getArgument(3));
        }
        for (Invocation call : mockingDetails(syslog).getInvocations()) {
            ObjectNode sent = answer.putObject("syslog");
            sent.put("protocol", ((SiemProtocol) call.getArgument(0)).name());
            sent.put("port", (int) call.getArgument(2));
            sent.put("message", hostnameAsToken((String) call.getArgument(3)));
            sent.put("timeoutSeconds", ((Duration) call.getArgument(4)).toSeconds());
            sent.put("label", (String) call.getArgument(5));
            Optional<?> pinned = call.getArgument(6);
            sent.put("pinnedCa", pinned.map(ca -> ((com.asmolabs.vectispire.common.domain.siem.CollectorCa) ca)
                    .subject()).orElse(null));
        }
    }

    /** The syslog HOSTNAME field, the third of the header, as a token: the sender reads it from the environment. */
    private static String hostnameAsToken(String message) {
        String[] parts = message.split(" ", 4);
        return parts[0] + " " + parts[1] + " {hostname} " + parts[3];
    }

    // ---- what a save does ----

    private record Row(boolean enabled, String protocol, String endpoint, String header, String ca, String minSeverity) {}

    private record Save(String name, Row before, boolean enabled, String protocol, String endpoint, String header,
            String minSeverity, String ca, boolean noticeFails) {}

    private static void saves(ArrayNode out) throws Exception {
        String root = fixture("01-root.pem");
        String expired = fixture("05-expired.pem");
        String damaged = root + fixture("02-issuing.pem").replaceFirst("-----BEGIN CERTIFICATE-----",
                "-----BEGIN CERTIFICATE");
        Row webhook = new Row(true, "WEBHOOK", "https://siem.example.com/e", "Bearer stored", null, "HIGH");
        Row udp = new Row(true, "SYSLOG_UDP", "127.0.0.1:514", null, null, "CRITICAL");
        Row tls = new Row(true, "SYSLOG_TLS", "c.example.com:6514", null, root, "HIGH");
        Row off = new Row(false, "SYSLOG_UDP", "127.0.0.1:514", null, null, "HIGH");
        Row lapsed = new Row(true, "SYSLOG_TLS", "c.example.com:6514", null, expired, "HIGH");
        Row staleHeader = new Row(true, "SYSLOG_UDP", "127.0.0.1:514", "Bearer stale", null, "HIGH");
        List<Save> cases = List.of(
                new Save("the first save", null, true, "WEBHOOK", "https://siem.example.com/e", "Bearer t", "HIGH",
                        null, false),
                new Save("defaults: no protocol, no minimum", null, false, null, null, null, null, null, false),
                new Save("blank protocol and minimum", null, false, " ", "", null, "\t", null, false),
                new Save("protocol and minimum in any case, trimmed", null, true, " syslog_udp ", "127.0.0.1:514",
                        null, " medium ", null, false),
                new Save("a minimum by Java's equalsIgnoreCase", null, true, "SYSLOG_UDP", "127.0.0.1:514", null,
                        "hıgh", null, false),
                new Save("an unknown protocol", null, true, " smtp ", "x", null, "HIGH", null, false),
                new Save("an unknown minimum", null, true, "WEBHOOK", "https://s.example/e", null, " severe ", null,
                        false),
                new Save("an endpoint past its column", null, true, "WEBHOOK",
                        "https://s.example/" + "a".repeat(1_100), null, "HIGH", null, false),
                new Save("an endpoint past its column once trimmed", null, true, "WEBHOOK",
                        " https://s.example/" + "a".repeat(1_006) + " ", null, "HIGH", null, false),
                new Save("an enabled export with no endpoint", null, true, "WEBHOOK", " ", null, "HIGH", null, false),
                new Save("a disabled export with no endpoint", null, false, "WEBHOOK", null, null, "HIGH", null,
                        false),
                new Save("a URL for syslog", null, true, "SYSLOG_TLS", "https://collector.example.com/cef", null, "HIGH",
                        null, false),
                new Save("host:port for a webhook", null, true, "WEBHOOK", "collector.example.com:514", null, "HIGH",
                        null, false),
                new Save("an endpoint refused even when disabled", null, false, "SYSLOG_UDP", "collector.example.com",
                        null, "HIGH", null, false),
                new Save("a header for syslog", null, true, "SYSLOG_TCP", "collector.example.com:514",
                        "Bearer never-sent", "HIGH", null, false),
                new Save("a header with a line break", null, true, "WEBHOOK", "https://s.example/e",
                        "Bearer a\nX-Injected: 1", "HIGH", null, false),
                new Save("a header with an accent", null, true, "WEBHOOK", "https://s.example/e", "Bearer é", "HIGH",
                        null, false),
                new Save("a header past 1500", null, true, "WEBHOOK", "https://s.example/e", "B".repeat(1_501), "HIGH",
                        null, false),
                new Save("a header trimmed to 1500", null, true, "WEBHOOK", "https://s.example/e",
                        " " + "B".repeat(1_500) + " ", "HIGH", null, false),
                new Save("a CA for another protocol", null, true, "SYSLOG_TCP", "c.example.com:514", null, "HIGH", root,
                        false),
                new Save("an expired CA", null, true, "SYSLOG_TLS", "c.example.com:6514", null, "HIGH", expired, false),
                new Save("a damaged bundle", null, true, "SYSLOG_TLS", "c.example.com:6514", null, "HIGH", damaged,
                        false),
                new Save("a CA pinned", null, true, "SYSLOG_TLS", "c.example.com:6514", null, "HIGH", root, false),
                new Save("a blank header keeps the stored one", webhook, true, "WEBHOOK", "https://siem.example.com/e",
                        "  ", "LOW", null, false),
                new Save("a moved endpoint drops the stored header", webhook, true, "WEBHOOK",
                        "https://collector.attacker.example/e", null, "HIGH", null, false),
                new Save("a moved endpoint with its own header", webhook, true, "WEBHOOK", "https://siem2.example.com/e",
                        " Bearer new ", "HIGH", null, false),
                new Save("the same endpoint, spaced, is not a move", webhook, true, "WEBHOOK",
                        "  https://siem.example.com/e  ", null, "HIGH", null, false),
                new Save("an omitted CA keeps the pinned one", tls, true, "SYSLOG_TLS", "c.example.com:6514", null,
                        "LOW", null, false),
                new Save("a blank CA removes it", tls, true, "SYSLOG_TLS", "c.example.com:6514", null, "HIGH", " ",
                        false),
                new Save("leaving TLS drops the CA", tls, true, "SYSLOG_TCP", "c.example.com:514", null, "HIGH", null,
                        false),
                new Save("switching off tells the collector", udp, false, "SYSLOG_UDP", "127.0.0.1:514", null,
                        "CRITICAL", null, false),
                new Save("redirecting tells the collector left", udp, true, "SYSLOG_UDP", "127.0.0.1:515", null,
                        "CRITICAL", null, false),
                new Save("another protocol to the same text is a move", udp, true, "SYSLOG_TCP", "127.0.0.1:514", null,
                        "CRITICAL", null, false),
                new Save("a new minimum leaves nobody", udp, true, "SYSLOG_UDP", "127.0.0.1:514", null, "HIGH", null,
                        false),
                new Save("a collector that cannot be told", udp, false, "SYSLOG_UDP", "127.0.0.1:514", null, "HIGH",
                        null, true),
                new Save("the webhook left is told with its header", webhook, false, "WEBHOOK",
                        "https://siem.example.com/e", null, "HIGH", null, false),
                new Save("an export already off tells nobody", off, false, "SYSLOG_UDP", "127.0.0.1:514", null, "HIGH",
                        null, false),
                new Save("a TLS collector left is told with its CA", tls, false, "SYSLOG_TLS", "c.example.com:6514",
                        null, "HIGH", null, false),
                new Save("a collector whose CA lapsed is not told", lapsed, false, "SYSLOG_TLS", "c.example.com:6514",
                        null, "HIGH", null, false),
                new Save("a syslog collector left is told without a stale header", staleHeader, false, "SYSLOG_UDP",
                        "127.0.0.1:514", null, "HIGH", null, false));
        for (Save input : cases) {
            ObjectNode row = out.addObject().put("name", input.name());
            if (input.before() != null) {
                row.putObject("before")
                        .put("enabled", input.before().enabled())
                        .put("protocol", input.before().protocol())
                        .put("endpoint", input.before().endpoint())
                        .put("header", input.before().header())
                        .put("ca", input.before().ca())
                        .put("minSeverity", input.before().minSeverity());
            }
            row.putObject("request")
                    .put("enabled", input.enabled())
                    .put("protocol", input.protocol())
                    .put("endpoint", input.endpoint())
                    .put("header", input.header())
                    .put("minSeverity", input.minSeverity())
                    .put("ca", input.ca())
                    .put("noticeFails", input.noticeFails());
            save(input, row.putObject("answer"));
        }
    }

    private static void save(Save input, ObjectNode answer) throws Exception {
        AtomicReference<SiemConfigEntity> stored = new AtomicReference<>();
        if (input.before() != null) {
            SiemConfigEntity before = new SiemConfigEntity();
            before.setId(SiemConfigEntity.SINGLETON_ID);
            before.setEnabled(input.before().enabled());
            before.setProtocol(input.before().protocol());
            before.setEndpoint(input.before().endpoint());
            before.setAuthHeader(input.before().header() == null ? null : "v2:" + input.before().header());
            before.setTlsCaPem(input.before().ca());
            before.setMinSeverity(input.before().minSeverity());
            // A whole second: the Rust side reads the row back from a real column, which MySQL keeps to the second.
            before.setCreatedAt(Instant.ofEpochSecond(NOW.getEpochSecond() - 3_600));
            before.setUpdatedAt(Instant.ofEpochSecond(NOW.getEpochSecond() - 3_600));
            stored.set(before);
        }
        SiemConfigRepository repository = mock(SiemConfigRepository.class);
        when(repository.findById(SiemConfigEntity.SINGLETON_ID)).thenAnswer(call -> Optional.ofNullable(stored.get()));
        when(repository.save(any())).thenAnswer(call -> {
            stored.set(call.getArgument(0));
            return call.getArgument(0);
        });
        EncryptionService encryption = mock(EncryptionService.class);
        when(encryption.encrypt(anyString(), eq(SiemExporterService.AUTH_HEADER_CONTEXT)))
                .thenAnswer(call -> "v2:" + call.getArgument(0));
        when(encryption.readSecret(any(), eq(SiemExporterService.AUTH_HEADER_CONTEXT), anyString())).thenAnswer(call -> {
            String value = call.getArgument(0);
            return value == null ? "" : value.substring(3);
        });
        SiemSender sender = mock(SiemSender.class);
        List<String> notices = new ArrayList<>();
        doAnswer(call -> {
            SiemEndpoint endpoint = call.getArgument(0);
            String header = call.getArgument(1);
            Optional<?> ca = call.getArgument(2);
            CefEvent event = call.getArgument(3);
            notices.add(describe(endpoint) + " | header=" + header + " | ca="
                    + ca.map(pinned -> ((com.asmolabs.vectispire.common.domain.siem.CollectorCa) pinned).subject())
                            .orElse(null)
                    + " | " + event.toCefString(VERSION));
            if (input.noticeFails()) {
                throw new OutboundJson.OutboundFailureException("SIEM export: closed");
            }
            return null;
        }).when(sender).send(any(), any(), any(), any());
        AuditLogService audit = mock(AuditLogService.class);
        SiemExporterService service =
                new SiemExporterService(repository, sender, encryption, audit, Clock.fixed(NOW, ZoneOffset.UTC));

        SiemConfigView view;
        try {
            view = service.saveConfig(input.enabled(), input.protocol(), input.endpoint(), input.header(),
                    input.minSeverity(), input.ca(), new RequestActor("admin", "10.0.0.1", "Mozilla/5.0"));
        } catch (IllegalArgumentException refused) {
            answer.put("refused", refused.getMessage());
            answer.put("written", false);
            return;
        }
        SiemConfigEntity row = stored.get();
        answer.putObject("row")
                .put("enabled", row.isEnabled())
                .put("protocol", row.getProtocol())
                .put("endpoint", row.getEndpoint())
                .put("header", row.getAuthHeader())
                .put("caSubject", view.tlsCaSubject())
                .put("caPem", row.getTlsCaPem())
                .put("minSeverity", row.getMinSeverity())
                .put("createdAt", row.getCreatedAt().toString())
                .put("updatedAt", row.getUpdatedAt().toString());
        answer.put("hasAuthHeader", view.hasAuthHeader());
        answer.put("caNotAfter", view.tlsCaNotAfter() == null ? null : view.tlsCaNotAfter().toString());
        ArrayNode notified = answer.putArray("notices");
        notices.forEach(notified::add);
        for (Invocation call : mockingDetails(audit).getInvocations()) {
            AuditLogService.Record entry = call.getArgument(0);
            answer.putObject("audit")
                    .put("operation", entry.operation().wireName())
                    .put("resourceId", entry.resourceId())
                    .put("description", entry.description())
                    .put("user", entry.userId())
                    .put("ip", entry.ipAddress())
                    .put("userAgent", entry.userAgent())
                    .put("signal", entry.signal() == null ? null : entry.signal().name());
        }
    }

    private static String describe(SiemEndpoint endpoint) {
        return switch (endpoint) {
            case SiemEndpoint.Webhook webhook -> "WEBHOOK " + webhook.url();
            case SiemEndpoint.Syslog syslog -> syslog.protocol().name() + " " + syslog.host() + " " + syslog.port();
        };
    }

    // ---- what the connection test answers ----

    private record Probe(String name, Row stored, String protocol, String endpoint, String header, String ca,
            String outcome) {}

    private static void tests(ArrayNode out) throws Exception {
        String root = fixture("01-root.pem");
        String expired = fixture("05-expired.pem");
        Row tls = new Row(true, "SYSLOG_TLS", "c.example.com:6514", null, root, "HIGH");
        Row udp = new Row(true, "SYSLOG_UDP", "127.0.0.1:514", null, null, "HIGH");
        Row unknown = new Row(true, "SMTP", "x", null, null, "HIGH");
        String damaged = root + fixture("02-issuing.pem").replaceFirst("-----BEGIN CERTIFICATE-----",
                "-----BEGIN CERTIFICATE");
        Row damagedTls = new Row(true, "SYSLOG_TLS", "c.example.com:6514", null, damaged, "HIGH");
        List<Probe> cases = List.of(
                new Probe("no endpoint", null, "WEBHOOK", null, null, null, "sent"),
                new Probe("a blank endpoint", null, "WEBHOOK", " ", null, null, "sent"),
                new Probe("a webhook delivered", null, "WEBHOOK", "https://s.example/e", "Bearer t", null, "sent"),
                new Probe("a webhook, header blank", null, null, "https://s.example/e", "  ", null, "sent"),
                new Probe("syslog delivered, the header not sent", null, "SYSLOG_UDP", "127.0.0.1:514", "Bearer t",
                        null, "sent"),
                new Probe("the stored protocol when none is given", udp, null, "127.0.0.1:514", null, null, "sent"),
                new Probe("the stored protocol unreadable: webhook", unknown, " ", "https://s.example/e", null, null,
                        "sent"),
                new Probe("an unknown protocol", null, "smtp", "https://s.example/e", null, null, "sent"),
                new Probe("an endpoint unusable for the protocol", null, "SYSLOG_TCP", "https://s.example/e", null,
                        null, "sent"),
                new Probe("the CA typed for the test", null, "SYSLOG_TLS", "c.example.com:6514", null, root, "sent"),
                new Probe("the stored CA when none is typed", tls, "SYSLOG_TLS", "c.example.com:6514", null, null,
                        "sent"),
                new Probe("a blank CA tests the runtime's store", tls, "SYSLOG_TLS", "c.example.com:6514", null, " ",
                        "sent"),
                new Probe("a stored bundle is read as it was accepted", damagedTls, "SYSLOG_TLS", "c.example.com:6514",
                        null, null, "sent"),
                new Probe("the same bundle typed is read as a paste", null, "SYSLOG_TLS", "c.example.com:6514", null,
                        damaged, "sent"),
                new Probe("an expired CA typed", null, "SYSLOG_TLS", "c.example.com:6514", null, expired, "sent"),
                new Probe("a CA typed for UDP is not read", null, "SYSLOG_UDP", "127.0.0.1:514", null, "not a pem",
                        "sent"),
                new Probe("refused by the policy", null, "WEBHOOK", "http://127.0.0.1:9/e", null, null, "unsafe"),
                new Probe("not delivered", null, "SYSLOG_TCP", "127.0.0.1:9", null, null, "failed"));
        for (Probe input : cases) {
            ObjectNode row = out.addObject().put("name", input.name());
            if (input.stored() != null) {
                row.putObject("stored")
                        .put("protocol", input.stored().protocol())
                        .put("endpoint", input.stored().endpoint())
                        .put("ca", input.stored().ca());
            }
            row.putObject("request")
                    .put("protocol", input.protocol())
                    .put("endpoint", input.endpoint())
                    .put("header", input.header())
                    .put("ca", input.ca())
                    .put("outcome", input.outcome());
            probe(input, row.putObject("answer"));
        }
    }

    private static void probe(Probe input, ObjectNode answer) throws Exception {
        SiemConfigRepository repository = mock(SiemConfigRepository.class);
        if (input.stored() != null) {
            SiemConfigEntity row = new SiemConfigEntity();
            row.setEnabled(true);
            row.setProtocol(input.stored().protocol());
            row.setEndpoint(input.stored().endpoint());
            row.setTlsCaPem(input.stored().ca());
            row.setMinSeverity(input.stored().minSeverity());
            when(repository.findById(SiemConfigEntity.SINGLETON_ID)).thenReturn(Optional.of(row));
        } else {
            when(repository.findById(SiemConfigEntity.SINGLETON_ID)).thenReturn(Optional.empty());
        }
        SiemSender sender = mock(SiemSender.class);
        List<String> sent = new ArrayList<>();
        var stub = doAnswer(call -> {
            SiemEndpoint endpoint = call.getArgument(0);
            String header = call.getArgument(1);
            Optional<?> ca = call.getArgument(2);
            CefEvent event = call.getArgument(3);
            sent.add(describe(endpoint) + " | header=" + header + " | ca="
                    + ca.map(pinned -> ((com.asmolabs.vectispire.common.domain.siem.CollectorCa) pinned).subject())
                            .orElse(null)
                    + " | " + event.toCefString(VERSION));
            switch (input.outcome()) {
                case "unsafe" -> throw new UnsafeUrlException("SIEM export: loopback refused");
                case "failed" -> throw new OutboundJson.OutboundFailureException("SIEM export: Connection refused");
                default -> {
                    return null;
                }
            }
        });
        stub.when(sender).send(any(), any(), any(), any());
        SiemExporterService service = new SiemExporterService(repository, sender, mock(EncryptionService.class),
                mock(AuditLogService.class), Clock.fixed(NOW, ZoneOffset.UTC));
        SiemExporterService.TestResult result =
                service.testConnection(input.protocol(), input.endpoint(), input.header(), input.ca());
        answer.put("success", result.success()).put("message", result.message()).put("statusCode", result.statusCode());
        ArrayNode attempts = answer.putArray("sent");
        sent.forEach(attempts::add);
    }

    private static String fixture(String name) throws Exception {
        return Files.readString(Path.of(System.getProperty("vectispire.rust.reference"), "siem", "collector-ca", name),
                StandardCharsets.UTF_8);
    }

    /** The text as the driver stores it: a lone surrogate becomes {@code ?}. */
    private static String stored(String text) {
        return new String(text.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }
}
