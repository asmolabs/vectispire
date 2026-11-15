package com.asmolabs.vectispire.core.agents;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.agents.AgentKind;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.RustReference;
import com.asmolabs.vectispire.core.access.AgentKeys;
import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * What the agents' administration answers, for the Rust port of {@code agents} (task 2.9 of the control plane's port):
 * {@code vectispire-rust/reference/agents/administration.json}.
 *
 * <p><b>The refusals and the audit sentences, input by input.</b> The replay holds the routes to what the Java suite
 * happened to send; this holds the service to the edges it did not — a name one UTF-16 unit past its column, labels
 * that normalise to what the row already holds, a limit changed on a row that had none, a key pinned for an agent
 * whose name needs escaping. An audit sentence is a record an auditor reads and a SIEM rule matches, so a word that
 * moves is a change of contract, not of style.
 *
 * <p>Each case runs the real {@link AgentAdministrationService} over a mocked repository, and is recorded with either
 * the refusal — its status as {@code ApiExceptionHandler} maps the exception, and its message — or the audit entries
 * written, in order, and the row as it was saved. The Rust side (`cp-agents/tests/administration_reference.rs`) puts
 * the same row in a real database, calls its service, and reads the same three things back.
 */
class AgentAdministrationReferenceSetTest {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;
    private static final Instant NOW = Instant.parse("2026-11-15T12:34:56.789Z");
    private static final RequestActor ACTOR = new RequestActor("admin", "203.0.113.7", "reference");
    private static final String KEY = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    /** An agent's name that needs escaping wherever it is quoted. */
    private static final String AWKWARD = "build \"β\" \\ 01";

    @Test
    void whatTheAdministrationAnswers() {
        ArrayNode cases = NODES.arrayNode();
        declarations(cases);
        changes(cases);
        signingKeys(cases);
        resets(cases);
        removals(cases);
        ObjectNode out = RustReference.object();
        out.put("key", KEY);
        out.set("cases", cases);
        RustReference.expect("agents/administration.json", out, AgentAdministrationReferenceSetTest.class);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Declarations

    private static void declarations(ArrayNode cases) {
        declare(cases, "declare-plain", "scanner-01", null, null, null, null);
        declare(cases, "declare-trimmed", "  scanner-02 \t", "  a description  ", " delegated ", " Linux , GPU,linux ", 4);
        declare(cases, "declare-null-name", null, null, null, null, null);
        declare(cases, "declare-blank-name", " \t ", null, null, null, null);
        declare(cases, "declare-name-at-its-bound", "n".repeat(249), null, null, null, null);
        declare(cases, "declare-name-past-its-bound", "n".repeat(250), null, null, null, null);
        // UTF-16 units, as `String.length` counts them: 124 emoji and a letter are 249, 125 emoji are 250.
        declare(cases, "declare-name-of-surrogates-at-its-bound", "🚀".repeat(124) + "a", null, null, null, null);
        declare(cases, "declare-name-of-surrogates-past-its-bound", "🚀".repeat(125), null, null, null, null);
        declare(cases, "declare-awkward-name", AWKWARD, null, null, null, null);
        // `String.trim` removes what is at or below U+0020, control characters included, and nothing else: a
        // no-break space is kept, and counts.
        declare(cases, "declare-name-padded-with-controls", "\u0001\u001Fscanner-03\u0000", null, null, null, null);
        declare(cases, "declare-name-padded-with-no-break-spaces", "\u00A0scanner-04\u00A0", null, null, null, null);
        declare(cases, "declare-name-of-no-break-spaces", "\u00A0\u2003", null, null, null, null);
        declare(cases, "declare-description-at-its-bound", "a1", "d".repeat(500), null, null, null);
        declare(cases, "declare-description-past-its-bound", "a2", "d".repeat(501), null, null, null);
        declare(cases, "declare-blank-description", "a3", "   ", null, null, null);
        declare(cases, "declare-mode-local", "m1", null, "local", null, null);
        declare(cases, "declare-mode-blank", "m2", null, "  ", null, null);
        declare(cases, "declare-mode-upper-case", "m3", null, "DELEGATED", null, null);
        declare(cases, "declare-mode-unknown", "m4", null, "remote-only", null, null);
        declare(cases, "declare-mode-unknown-padded", "m5", null, "  remote-only\t", null, null);
        declare(cases, "declare-mode-padded-with-a-no-break-space", "m6", null, "\u00A0local", null, null);
        declare(cases, "declare-labels-blank", "l1", null, null, " , ,", null);
        // Lower-cased under the root locale, so the dotted capital I keeps its dot as a combining mark.
        declare(cases, "declare-labels-beyond-ascii", "l4", null, null, "GPU,\u00C9T\u00C9,\u0130stanbul, \u00A0arm ", null);
        declare(cases, "declare-labels-past-their-bound", "l2", null, null, ("x".repeat(40) + ",").repeat(7), null);
        declare(cases, "declare-labels-of-one-past-their-bound", "l3", null, null, "y".repeat(256), null);
        declare(cases, "declare-concurrency-zero", "c1", null, null, null, 0);
        declare(cases, "declare-concurrency-negative", "c2", null, null, null, -3);
        declare(cases, "declare-concurrency-one", "c3", null, null, null, 1);
        declare(cases, "declare-concurrency-at-its-bound", "c4", null, null, null, 16);
        declare(cases, "declare-concurrency-past-its-bound", "c5", null, null, null, 17);
    }

    private static void declare(
            ArrayNode cases, String name, String agentName, String description, String mode, String labels, Integer max) {
        ObjectNode input = NODES.objectNode();
        input.put("name", agentName);
        input.put("description", description);
        input.put("credentialsMode", mode);
        input.put("labels", labels);
        input.put("maxConcurrent", max);
        cases.add(run(name, "declare", null, input, null, service -> {
            AgentAdministrationService.Declared declared = service.declare(
                    new AgentAdministrationService.Declaration(agentName, description, mode, labels, max), ACTOR);
            ObjectNode answer = NODES.objectNode();
            answer.put("secretIssued", declared.secret() != null && !declared.secret().isBlank());
            return answer;
        }));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Changes

    private static void changes(ArrayNode cases) {
        ObjectNode plain = prior("scanner-01", "linux,gpu", true, 2);
        change(cases, "change-nothing", plain, null, null, null);
        change(cases, "change-labels", plain, null, "arm64 , Linux", null);
        change(cases, "change-labels-to-what-they-normalise-to", plain, null, " GPU , linux ", null);
        change(cases, "change-labels-to-none", plain, null, " , ", null);
        change(cases, "change-labels-past-their-bound", plain, null, "z".repeat(256), null);
        change(cases, "change-disable", plain, false, null, null);
        change(cases, "change-enable-an-enabled-agent", plain, true, null, null);
        change(cases, "change-concurrency", plain, null, null, 8);
        change(cases, "change-concurrency-to-the-same", plain, null, null, 2);
        change(cases, "change-concurrency-past-its-bound", plain, null, null, 17);
        change(cases, "change-concurrency-zero", plain, null, null, 0);
        change(cases, "change-everything", plain, false, "windows", 3);
        ObjectNode bare = prior(AWKWARD, null, false, null);
        change(cases, "change-labels-of-an-agent-with-none", bare, null, "linux", null);
        change(cases, "change-reenable", bare, true, null, null);
        // A row written before the limit was a column: no limit, read as the default.
        change(cases, "change-concurrency-of-an-agent-with-none", bare, null, null, 2);
        change(cases, "change-concurrency-to-the-default-of-an-agent-with-none", bare, null, null, 1);
        change(cases, "change-unknown-agent", null, true, null, null);
    }

    private static void change(ArrayNode cases, String name, ObjectNode prior, Boolean enabled, String labels, Integer max) {
        ObjectNode input = NODES.objectNode();
        input.put("enabled", enabled);
        input.put("labels", labels);
        input.put("maxConcurrent", max);
        cases.add(run(name, "change", prior, input, null, service -> {
            AgentAdministrationService.Changed changed =
                    service.change(ID, new AgentAdministrationService.Change(enabled, labels, max), ACTOR);
            ObjectNode answer = NODES.objectNode();
            answer.put("enabled", changed.enabled());
            answer.put("labels", changed.labels());
            return answer;
        }));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Signing keys, sealing keys, removals

    private static void signingKeys(ArrayNode cases) {
        ObjectNode agent = prior(AWKWARD, "linux", true, 2);
        pin(cases, "pin-a-key", agent, KEY);
        pin(cases, "pin-a-padded-key", agent, "  " + KEY + "\n");
        pin(cases, "pin-a-key-padded-with-a-no-break-space", agent, "\u00A0" + KEY);
        pin(cases, "pin-generated-padded", agent, "\tgenerate ");
        pin(cases, "pin-generated", agent, "generate");
        pin(cases, "pin-generated-upper-case", agent, "GENERATE");
        pin(cases, "pin-not-a-key", agent, "not a key");
        pin(cases, "pin-a-short-key", agent, "AAAA");
        pin(cases, "pin-removed", agent, null);
        pin(cases, "pin-removed-by-blank", agent, "  ");
        pin(cases, "pin-unknown-agent", null, KEY);
    }

    private static void pin(ArrayNode cases, String name, ObjectNode prior, String key) {
        ObjectNode input = NODES.objectNode();
        input.put("publicKey", key);
        cases.add(run(name, "pin", prior, input, null, service -> {
            AgentAdministrationService.PinnedKey pinned = service.pinSigningKey(ID, key, ACTOR);
            ObjectNode answer = NODES.objectNode();
            answer.put("signsResults", pinned.signsResults());
            answer.put("privateKeyReturned", pinned.privateKey() != null);
            return answer;
        }));
    }

    private static void resets(ArrayNode cases) {
        cases.add(run("reset-sealing-key", "reset", prior(AWKWARD, null, true, null), NODES.objectNode(), null, service -> {
            service.resetSealingKey(ID, ACTOR);
            return NODES.objectNode();
        }));
        cases.add(run("reset-unknown-agent", "reset", null, NODES.objectNode(), null, service -> {
            service.resetSealingKey(ID, ACTOR);
            return NODES.objectNode();
        }));
    }

    private static void removals(ArrayNode cases) {
        remove(cases, "remove-idle", prior(AWKWARD, "linux", true, 2), 0);
        remove(cases, "remove-running-one", prior("scanner-01", null, true, 2), 1);
        remove(cases, "remove-running-three", prior("scanner-01", null, false, 4), 3);
        remove(cases, "remove-unknown-agent", null, 0);
    }

    private static void remove(ArrayNode cases, String name, ObjectNode prior, long running) {
        cases.add(run(name, "remove", prior, NODES.objectNode(), running, service -> {
            service.remove(ID, ACTOR);
            return NODES.objectNode();
        }));
    }

    // ---------------------------------------------------------------------------------------------------------
    // The service over mocks, and what a case records

    private static final UUID ID = UUID.fromString("0b9a3c52-6f1e-4d1a-9c55-2f0e7a4b8d10");

    private static ObjectNode prior(String name, String labels, boolean enabled, Integer maxConcurrent) {
        ObjectNode prior = NODES.objectNode();
        prior.put("name", name);
        prior.put("labels", labels);
        prior.put("enabled", enabled);
        prior.put("maxConcurrent", maxConcurrent);
        return prior;
    }

    private static ObjectNode run(
            String name,
            String operation,
            ObjectNode prior,
            ObjectNode input,
            Long running,
            Function<AgentAdministrationService, ObjectNode> call) {
        AgentRepository agents = mock(AgentRepository.class);
        AgentKeys keys = mock(AgentKeys.class);
        ScanCatalog scans = mock(ScanCatalog.class);
        AuditLogService audit = mock(AuditLogService.class);
        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

        AgentEntity existing = null;
        if (prior != null) {
            existing = new AgentEntity();
            existing.setId(ID);
            existing.setName(prior.get("name").asText());
            existing.setKind(AgentKind.REMOTE.wireName());
            existing.setCredentialsMode("local");
            existing.setLabels(prior.get("labels").isNull() ? null : prior.get("labels").asText());
            existing.setEnabled(prior.get("enabled").asBoolean());
            existing.setMaxConcurrent(prior.get("maxConcurrent").isNull() ? null : prior.get("maxConcurrent").asInt());
            existing.setSigningPublicKey(KEY);
            existing.setCreatedAt(NOW);
        }
        when(agents.findById(ID)).thenReturn(Optional.ofNullable(existing));
        List<AgentEntity> saved = new ArrayList<>();
        when(agents.save(any())).thenAnswer(invocation -> {
            AgentEntity entity = invocation.getArgument(0);
            if (entity.getId() == null) {
                entity.setId(ID);
            }
            saved.add(entity);
            return entity;
        });
        when(keys.issue(anyString(), any(), any())).thenReturn(UUID.fromString("7d0c1f3e-2b4a-4e6f-8a9b-0c1d2e3f4a5b"));
        when(scans.countWithStatusClaimedBy(ScanStatus.SCANNING.wireName(), ID.toString())).thenReturn(running == null ? 0L : running);
        List<AuditLogService.Record> entries = new ArrayList<>();
        doAnswer(invocation -> {
            entries.add(invocation.getArgument(0));
            return null;
        }).when(audit).record(any(AuditLogService.Record.class));

        AgentAdministrationService service = new AgentAdministrationService(
                agents,
                keys,
                scans,
                mock(TargetCatalog.class),
                audit,
                mock(BuiltInWorker.class),
                new TransactionTemplate(manager),
                Clock.fixed(NOW, ZoneOffset.UTC));

        ObjectNode recorded = NODES.objectNode();
        recorded.put("name", name);
        recorded.put("operation", operation);
        recorded.set("prior", prior == null ? NODES.nullNode() : prior);
        recorded.set("input", input);
        if (running != null) {
            recorded.put("running", running);
        }
        ObjectNode outcome = NODES.objectNode();
        try {
            outcome.set("answer", call.apply(service));
        } catch (InvalidInputException refused) {
            outcome.set("refused", refusal(400, refused.getMessage()));
        } catch (NotFoundException absent) {
            outcome.set("refused", refusal(404, absent.getMessage()));
        }
        ArrayNode audited = NODES.arrayNode();
        for (AuditLogService.Record entry : entries) {
            ObjectNode line = NODES.objectNode();
            line.put("operation", entry.operation().name());
            line.put("resourceId", entry.resourceId());
            line.put("description", entry.description());
            line.put("userId", entry.userId());
            audited.add(line);
        }
        outcome.set("audit", audited);
        if (!saved.isEmpty()) {
            AgentEntity row = saved.getLast();
            ObjectNode stored = NODES.objectNode();
            stored.put("name", row.getName());
            stored.put("description", row.getDescription());
            stored.put("credentialsMode", row.getCredentialsMode());
            stored.put("labels", row.getLabels());
            stored.put("enabled", row.getEnabled());
            stored.put("maxConcurrent", row.getMaxConcurrent());
            stored.put("signsResults", row.getSigningPublicKey() != null);
            outcome.set("stored", stored);
        }
        recorded.set("outcome", outcome);
        return recorded;
    }

    private static ObjectNode refusal(int status, String detail) {
        ObjectNode refused = NODES.objectNode();
        refused.put("status", status);
        refused.put("detail", detail);
        return refused;
    }
}
