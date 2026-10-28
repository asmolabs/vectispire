package com.asmolabs.vectispire.core.outbox;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.notifications.NotificationPayload;
import com.asmolabs.vectispire.common.domain.notifications.OutboxRetry;
import com.asmolabs.vectispire.core.RustReference;
import com.asmolabs.vectispire.core.outbox.internal.NotificationRelayTask;
import com.asmolabs.vectispire.core.outbox.internal.SentMessagesTask;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageEntity;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.Invocation;
import org.springframework.data.domain.Limit;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * What the relay does, call by call — the Rust control plane's {@code cp-outbox} is held to it
 * ({@code vectispire-rust/reference/outbox/relay.json}).
 *
 * <p><b>Run, never restated.</b> Each scenario is the real {@link OutboxService} over a mocked repository and a fixed
 * clock, as {@code OutboxServiceTest} builds it, and the reference is the list of repository calls it made, with their
 * arguments, in order: which rows it claimed, with which window, what it recorded for each failure — the attempt, the
 * status, the next attempt, the reason as {@code last_error} keeps it — and what it marked sent. A Rust relay over a
 * recording store must make the same calls. The backoff table, the stamped payloads and the rows {@code enqueue} saves
 * are written the same way, from {@link OutboxRetry} and from the entity handed to {@code save}.
 *
 * <p><b>Every text is written as the database receives it.</b> {@code OutboxRetry.recordableError} cuts at 500 UTF-16
 * units and can split a surrogate pair; the drivers encode such a string with {@code getBytes(UTF_8)}, which writes the
 * lone half as {@code ?}. That is what a row holds, and what is written here.
 */
class OutboxReferenceSetTest {

    private static final Instant NOW = Instant.parse("2026-10-17T09:30:00.123456Z");
    private static final ObjectMapper JSON = new ObjectMapper();
    /** Stands for the random message id in the stamped payloads. */
    private static final String ID_TOKEN = "{message_id}";

    /** A scan delta as {@code enqueue} leaves it: stamped with its row's identifier, which is how a channel is told apart. */
    private static String delta(String id) {
        return "{\"scan_id\":7,\"new_count\":2,\"reopened_count\":0,\"message_id\":\"" + id + "\"}";
    }

    @Test
    void theRelayTheBackoffAndTheStampedRows() throws Exception {
        ObjectNode out = RustReference.object();
        constants(out.putObject("constants"));
        backoff(out.putArray("backoff"));
        recordable(out.putArray("recordableErrors"));
        stamped(out.putArray("enqueued"));
        scenarios(out.putArray("scenarios"));
        RustReference.expect("outbox/relay.json", out, OutboxReferenceSetTest.class);
    }

    private static void constants(ObjectNode out) {
        out.put("maxAttempts", OutboxRetry.MAX_ATTEMPTS);
        out.put("baseBackoffSeconds", OutboxRetry.BASE_BACKOFF.toSeconds());
        out.put("maxBackoffSeconds", OutboxRetry.MAX_BACKOFF.toSeconds());
        out.put("maxPerPass", OutboxRetry.MAX_PER_PASS);
        out.put("claimWindowSeconds", OutboxRetry.CLAIM_WINDOW.toSeconds());
        out.put("sentRetentionSeconds", OutboxRetry.SENT_RETENTION.toSeconds());
        out.put("scanDeltaType", OutboxService.TYPE_SCAN_DELTA);
    }

    /** Every attempt count a row can hold, a corrupted one included: the shift is capped, never wrapped. */
    private static void backoff(ArrayNode out) {
        for (int attempts : new int[] {Integer.MIN_VALUE, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 20, 21, 22, 64, Integer.MAX_VALUE}) {
            ObjectNode row = out.addObject();
            row.put("attempts", attempts);
            row.put("backoffSeconds", OutboxRetry.backoff(attempts).toSeconds());
            row.put("abandoned", OutboxRetry.isAbandoned(attempts));
            row.put("nextAttemptAt", OutboxRetry.nextAttemptAt(attempts, NOW).map(Instant::toString).orElse(null));
        }
    }

    private static void recordable(ArrayNode out) {
        List<RuntimeException> errors = List.of(
                new IllegalStateException("connection refused"),
                new IllegalStateException(),
                new IllegalArgumentException(""),
                new IllegalStateException("x".repeat(600)),
                // The prefix is 23 units: the pair straddles unit 500 and is cut in half.
                new IllegalStateException("y".repeat(476) + "\uD83D\uDE00" + "z".repeat(40)),
                new IllegalStateException("é".repeat(600)));
        for (RuntimeException error : errors) {
            ObjectNode row = out.addObject();
            row.put("kind", error.getClass().getSimpleName());
            row.put("message", error.getMessage() == null ? null : stored(error.getMessage()));
            row.put("recorded", stored(OutboxRetry.recordableError(error)));
        }
    }

    /** What {@code enqueue} saves, for payloads given as JSON text. */
    private static void stamped(ArrayNode out) throws Exception {
        List<String> payloads = List.of(
                "{\"scan_id\":7}",
                "{}",
                "{\"scan_id\":7,\"message_id\":\"from-the-caller\",\"after\":true}",
                "{\"nested\":{\"list\":[1,2,{\"a\":null}],\"empty\":[]},\"text\":\"quote \\\" backslash \\\\ slash /\"}",
                "{\"controls\":\"\\u0000\\u0001\\u001f\\b\\f\\n\\r\\t\\u007f\",\"unicode\":\"é – ✓ 😀 \\u2028\"}",
                "{\"epss\":0.4,\"count\":-12,\"big\":9007199254740993,\"zero\":0.0,\"flag\":false}");
        Long[] teams = {null, 42L};
        for (String payload : payloads) {
            for (Long team : teams) {
                OutboxMessageRepository messages = mock(OutboxMessageRepository.class);
                when(messages.save(any())).thenAnswer(call -> call.getArgument(0));
                OutboxService service = service(messages, List.of(), List.of());
                String type = team == null ? "siem_event" : OutboxService.TYPE_SCAN_DELTA;
                UUID id = service.enqueue(JSON.readTree(payload), type, team);
                OutboxMessageEntity saved = (OutboxMessageEntity) mockingDetails(messages).getInvocations().stream()
                        .filter(call -> call.getMethod().getName().equals("save"))
                        .findFirst()
                        .orElseThrow()
                        .getArgument(0);
                // The id is random, so the file holds it as a token: the payload with the row's id replaced, and
                // whether `enqueue` returned the row's id and the payload names it — the facts, not the value.
                ObjectNode row = out.addObject();
                row.put("input", payload);
                row.put("returnsTheRowsId", id.equals(saved.getId()));
                row.put("payloadNamesTheId", saved.getPayload().contains("\"" + saved.getId() + "\""));
                row.put("message_type", saved.getMessageType());
                row.put("payload", stored(saved.getPayload()).replace(saved.getId().toString(), ID_TOKEN));
                if (saved.getTeamId() == null) {
                    row.putNull("team_id");
                } else {
                    row.put("team_id", saved.getTeamId());
                }
                row.put("status", saved.getStatus());
                row.put("attempts", saved.getAttempts());
                row.put("next_attempt_at", saved.getNextAttemptAt() == null ? null : saved.getNextAttemptAt().toString());
                row.put("last_error", saved.getLastError());
                row.put("created_at", saved.getCreatedAt().toString());
                row.put("sent_at", saved.getSentAt() == null ? null : saved.getSentAt().toString());
            }
        }
    }

    // ── the relay ───────────────────────────────────────────────────────────────────────────────────────────────

    /** A row as the due query hands it over. */
    private record Due(String id, String type, Long team, String payload, int attempts, boolean claimable) {
        static Due of(String id, String type, int attempts) {
            return new Due(id, type, null, delta(id), attempts, true);
        }
    }

    /** What a destination does with the row it is handed: nothing (delivered), or it throws. */
    private record Outcome(String gone, RuntimeException failure) {
        static final Outcome DELIVERED = new Outcome(null, null);

        static Outcome fails(RuntimeException error) {
            return new Outcome(null, error);
        }

        static Outcome gone(String reason) {
            return new Outcome(reason, null);
        }

        void apply() {
            if (gone != null) {
                throw new GoneDestinationException(gone);
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    private record Scenario(
            String name, List<String> handlers, List<String> channels, List<Due> due, Map<String, Outcome> outcomes) {}

    private static final String A = "00000000-0000-0000-0000-00000000000a";
    private static final String B = "00000000-0000-0000-0000-00000000000b";

    private static void scenarios(ArrayNode out) throws Exception {
        List<String> channels = List.of(OutboxService.TYPE_SCAN_DELTA, "scan_delta_teams");
        List<String> handlers = List.of("siem_event");
        List<Scenario> all = new ArrayList<>();
        all.add(new Scenario("delivered", handlers, channels, List.of(Due.of(A, "scan_delta", 0)), Map.of(A, Outcome.DELIVERED)));
        for (int before = 0; before < OutboxRetry.MAX_ATTEMPTS; before++) {
            all.add(new Scenario("failed after " + before + " attempts", handlers, channels,
                    List.of(Due.of(A, "scan_delta", before)),
                    Map.of(A, Outcome.fails(new IllegalStateException("connection refused")))));
        }
        all.add(new Scenario("a corrupted counter is abandoned", handlers, channels, List.of(Due.of(A, "scan_delta", 1000)),
                Map.of(A, Outcome.fails(new IllegalStateException("connection refused")))));
        all.add(new Scenario("a negative counter waits the base backoff", handlers, channels,
                List.of(Due.of(A, "scan_delta", -5)), Map.of(A, Outcome.fails(new IllegalStateException("boom")))));
        all.add(new Scenario("delivered on the last attempt", handlers, channels,
                List.of(Due.of(A, "scan_delta", OutboxRetry.MAX_ATTEMPTS - 1)), Map.of(A, Outcome.DELIVERED)));
        all.add(new Scenario("claimed by another instance", handlers, channels,
                List.of(new Due(A, "scan_delta", null, delta(A), 0, false)), Map.of(A, Outcome.DELIVERED)));
        all.add(new Scenario("one failure does not undo the other delivery", handlers, channels,
                List.of(Due.of(A, "scan_delta", 0), Due.of(B, "scan_delta", 2)),
                Map.of(A, Outcome.fails(new IllegalStateException("boom")), B, Outcome.DELIVERED)));
        all.add(new Scenario("the second of two claimed elsewhere", handlers, channels,
                List.of(Due.of(A, "scan_delta", 0), new Due(B, "scan_delta", null, delta(B), 0, false)),
                Map.of(A, Outcome.DELIVERED, B, Outcome.DELIVERED)));
        all.add(new Scenario("a type nobody handles", handlers, channels,
                List.of(Due.of(A, "scan_delta_carrier_pigeon", 0)), Map.of()));
        all.add(new Scenario("a type nobody handles, on its last attempt", handlers, channels,
                List.of(Due.of(A, "scan_delta_carrier_pigeon", OutboxRetry.MAX_ATTEMPTS - 1)), Map.of()));
        all.add(new Scenario("a type nobody handles, with nobody registered", List.of(), List.of(),
                List.of(Due.of(A, "siem_event", 0)), Map.of()));
        all.add(new Scenario("a handler's row", handlers, channels,
                List.of(new Due(A, "siem_event", null, "{\"event\":\"x\",\"message_id\":\"" + A + "\"}", 0, true)),
                Map.of(A, Outcome.DELIVERED)));
        all.add(new Scenario("a handler's destination gone", handlers, channels, List.of(Due.of(A, "siem_event", 3)),
                Map.of(A, Outcome.gone("the SIEM export was switched off"))));
        all.add(new Scenario("a channel's destination gone", handlers, channels,
                List.of(new Due(A, "scan_delta", 99L, delta(A), 0, true)), Map.of(A, Outcome.gone("team 99 no longer exists"))));
        all.add(new Scenario("a gone reason is kept whole", handlers, channels, List.of(Due.of(A, "siem_event", 0)),
                Map.of(A, Outcome.gone("g".repeat(700)))));
        all.add(new Scenario("a failure without a message", handlers, channels, List.of(Due.of(A, "siem_event", 0)),
                Map.of(A, Outcome.fails(new IllegalStateException()))));
        all.add(new Scenario("a long failure is cut", handlers, channels, List.of(Due.of(A, "scan_delta", 0)),
                Map.of(A, Outcome.fails(new IllegalStateException("y".repeat(476) + "\uD83D\uDE00" + "z".repeat(40))))));
        all.add(new Scenario("a team's copy goes to the type's channel with its team", handlers, channels,
                List.of(new Due(A, "scan_delta_teams", 42L, delta(A), 0, true), new Due(B, "scan_delta", 7L, delta(B), 0, true)),
                Map.of(A, Outcome.DELIVERED, B, Outcome.DELIVERED)));
        for (Scenario scenario : all) {
            out.add(run(scenario));
        }

        // The two tasks, over the same service: the batch the relay task asks for, and the purge's cutoff.
        ObjectNode relayTask = out.addObject();
        relayTask.put("name", "the relay task");
        OutboxMessageRepository messages = mock(OutboxMessageRepository.class);
        when(messages.findDue(anyString(), any(), any())).thenReturn(List.of());
        clearInvocations(messages);
        new NotificationRelayTask(service(messages, List.of(), List.of())).run();
        relayTask.set("calls", calls(messages));

        ObjectNode purge = out.addObject();
        purge.put("name", "the purge task");
        messages = mock(OutboxMessageRepository.class);
        when(messages.deleteSentBefore(anyString(), any())).thenReturn(3);
        clearInvocations(messages);
        OutboxService service = service(messages, List.of(), List.of());
        purge.put("pruned", service.pruneSent());
        new SentMessagesTask(service).run();
        purge.set("calls", calls(messages));

        ObjectNode counts = out.addObject();
        counts.put("name", "the counts");
        messages = mock(OutboxMessageRepository.class);
        when(messages.countByStatus())
                .thenReturn(List.of(new Object[] {"sent", 4L}, new Object[] {"failed", 1L}, new Object[] {"pending", 12L}));
        counts.set("counts", JSON.valueToTree(new TreeMap<>(service(messages, List.of(), List.of()).counts())));
    }

    private static ObjectNode run(Scenario scenario) throws Exception {
        OutboxMessageRepository messages = mock(OutboxMessageRepository.class);
        List<OutboxMessageEntity> due = new ArrayList<>();
        for (Due row : scenario.due()) {
            OutboxMessageEntity message = new OutboxMessageEntity();
            message.setId(UUID.fromString(row.id()));
            message.setMessageType(row.type());
            message.setTeamId(row.team());
            message.setPayload(row.payload());
            message.setStatus("pending");
            message.setAttempts(row.attempts());
            message.setCreatedAt(NOW.minusSeconds(600));
            due.add(message);
            when(messages.claim(UUID.fromString(row.id()), "pending", NOW, NOW.plus(OutboxRetry.CLAIM_WINDOW)))
                    .thenReturn(row.claimable() ? 1 : 0);
        }
        when(messages.findDue(anyString(), any(), any())).thenReturn(due);
        clearInvocations(messages);

        ArrayNode delivered = JSON.createArrayNode();
        List<OutboxHandler> handlers = scenario.handlers().stream()
                .<OutboxHandler>map(type -> new OutboxHandler() {
                    @Override
                    public String type() {
                        return type;
                    }

                    @Override
                    public void deliver(UUID messageId, String payload) {
                        ObjectNode call = delivered.addObject();
                        call.put("to", "handler " + type);
                        call.put("id", messageId.toString());
                        call.put("payload", payload);
                        scenario.outcomes().get(messageId.toString()).apply();
                    }
                })
                .toList();
        Function<String, NotificationChannel> channel = type -> new NotificationChannel() {
            @Override
            public String type() {
                return type;
            }

            @Override
            public boolean isConfigured() {
                return true;
            }

            @Override
            public void deliver(NotificationPayload payload) {
                throw new AssertionError("the relay hands a channel its row's team");
            }

            @Override
            public void deliver(NotificationPayload payload, Long teamId) {
                ObjectNode call = delivered.addObject();
                call.put("to", "channel " + type);
                call.put("id", payload.messageId());
                if (teamId == null) {
                    call.putNull("team");
                } else {
                    call.put("team", teamId);
                }
                scenario.outcomes().get(payload.messageId()).apply();
            }
        };
        OutboxService service = service(messages, scenario.channels().stream().map(channel).toList(), handlers);
        OutboxService.RelayResult result = service.relay(OutboxRetry.MAX_PER_PASS);

        ObjectNode row = JSON.createObjectNode();
        row.put("name", scenario.name());
        row.set("handlers", JSON.valueToTree(scenario.handlers()));
        row.set("channels", JSON.valueToTree(scenario.channels()));
        ArrayNode rows = row.putArray("due");
        for (Due each : scenario.due()) {
            ObjectNode r = rows.addObject();
            r.put("id", each.id());
            r.put("message_type", each.type());
            if (each.team() == null) {
                r.putNull("team_id");
            } else {
                r.put("team_id", each.team());
            }
            r.put("payload", each.payload());
            r.put("attempts", each.attempts());
            r.put("claimable", each.claimable());
            Outcome outcome = scenario.outcomes().get(each.id());
            r.put("outcome", outcome == null ? "unreached"
                    : outcome.gone() != null ? "gone"
                    : outcome.failure() != null ? "fails" : "delivered");
            if (outcome != null && outcome.gone() != null) {
                r.put("reason", outcome.gone());
            }
            if (outcome != null && outcome.failure() != null) {
                r.put("kind", outcome.failure().getClass().getSimpleName());
                r.put("message", outcome.failure().getMessage() == null ? null : stored(outcome.failure().getMessage()));
            }
        }
        row.set("calls", calls(messages));
        row.set("delivered", delivered);
        ObjectNode settled = row.putObject("result");
        settled.put("sent", result.sent());
        settled.put("failed", result.failed());
        settled.put("abandoned", result.abandoned());
        return row;
    }

    /** The repository calls, in order, each with its arguments as the database receives them. */
    private static ArrayNode calls(OutboxMessageRepository messages) {
        ArrayNode out = JSON.createArrayNode();
        for (Invocation invocation : mockingDetails(messages).getInvocations()) {
            ObjectNode call = out.addObject();
            call.put("method", invocation.getMethod().getName());
            ArrayNode args = call.putArray("args");
            for (Object argument : invocation.getArguments()) {
                switch (argument) {
                    case null -> args.addNull();
                    case Limit limit -> args.add(limit.max());
                    case Integer number -> args.add(number);
                    case String text -> args.add(stored(text));
                    default -> args.add(argument.toString());
                }
            }
        }
        return out;
    }

    private static OutboxService service(
            OutboxMessageRepository messages, List<NotificationChannel> channels, List<OutboxHandler> handlers) {
        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        return new OutboxService(messages, channels, handlers, JSON, Clock.fixed(NOW, ZoneOffset.UTC),
                new TransactionTemplate(manager));
    }

    /** The text as the driver stores it: a lone surrogate becomes {@code ?}. */
    private static String stored(String text) {
        return new String(text.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }
}
