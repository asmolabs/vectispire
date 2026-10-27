package com.asmolabs.vectispire.common.domain.siem;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * What the SIEM domain answers for {@code siem/inputs.json} — the answers the Rust port
 * ({@code vectispire_domain::siem}) is held to, byte for byte.
 *
 * <p>Everything here leaves the system: the CEF line a SOC's parser splits, the syslog header a collector routes
 * on, the wire names a queued message stores, the refusal an operator reads. The inputs sit where a port would
 * drift: the escapes and the control characters, a key given twice to a {@code LinkedHashMap}, Java's
 * {@code isBlank} and {@code trim}, an IPv4-mapped address in brackets, a full-width digit in a port.
 */
class SiemReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void theAnswersTheRustSiemDomainIsHeldTo() throws Exception {
        JsonNode inputs = JSON.readTree(ReferenceSet.read("siem/inputs.json"));
        ObjectNode answers = JSON.createObjectNode();

        ArrayNode catalogue = answers.putArray("catalogue");
        for (SecurityEventType type : SecurityEventType.values()) {
            catalogue.addObject()
                    .put("name", type.name())
                    .put("signatureId", type.signatureId())
                    .put("description", type.description())
                    .put("cefSeverity", type.cefSeverity())
                    .put("outcome", type.outcome().wireName())
                    .put("followsIssueSeverity", type.followsIssueSeverity());
        }

        ArrayNode signalled = answers.putArray("signalledBy");
        for (AuditOperation operation : AuditOperation.values()) {
            signalled.addObject()
                    .put("operation", operation.name())
                    .put("event", SecurityEventType.signalledBy(operation).map(Enum::name).orElse(null));
        }

        ArrayNode cef = answers.putArray("cef");
        for (JsonNode input : inputs.path("cef")) {
            ObjectNode answer = cef.addObject().put("name", input.path("name").asText());
            try {
                answer.put("line", event(input).toCefString(text(input.path("version"))));
            } catch (IllegalArgumentException | IllegalStateException refused) {
                answer.put("refused", refused.getMessage());
            }
        }

        ArrayNode syslog = answers.putArray("syslog");
        for (JsonNode input : inputs.path("syslog")) {
            syslog.addObject()
                    .put("name", input.path("name").asText())
                    .put("message", SyslogMessage.format(event(input), text(input.path("hostname")),
                            input.path("cef").asText()));
        }

        ArrayNode frames = answers.putArray("frames");
        for (JsonNode input : inputs.path("frames")) {
            byte[] frame = SyslogMessage.octetCounted(input.asText());
            frames.addObject().put("bytes", frame.length).put("frame", new String(frame, StandardCharsets.UTF_8));
        }

        ArrayNode endpoints = answers.putArray("endpoints");
        for (JsonNode input : inputs.path("endpoints")) {
            ObjectNode answer = endpoints.addObject()
                    .put("protocol", input.path("protocol").asText())
                    .put("endpoint", text(input.path("endpoint")));
            try {
                switch (SiemEndpoint.parse(SiemProtocol.valueOf(input.path("protocol").asText()),
                        text(input.path("endpoint")))) {
                    case SiemEndpoint.Webhook webhook -> answer.put("webhook", webhook.url());
                    case SiemEndpoint.Syslog target -> answer.putObject("syslog")
                            .put("protocol", target.protocol().name())
                            .put("host", target.host())
                            .put("port", target.port());
                }
            } catch (IllegalArgumentException refused) {
                answer.put("refused", refused.getMessage());
            }
        }

        ArrayNode protocols = answers.putArray("protocols");
        for (JsonNode input : inputs.path("protocols")) {
            protocols.addObject()
                    .put("value", text(input))
                    .put("protocol", SiemProtocol.byName(text(input)).map(Enum::name).orElse(null))
                    .put("carriesHeaders", SiemProtocol.byName(text(input)).map(SiemProtocol::carriesHeaders)
                            .orElse(null));
        }

        ArrayNode minimums = answers.putArray("minimums");
        for (JsonNode input : inputs.path("minimums")) {
            ObjectNode answer = minimums.addObject().put("value", text(input));
            answer.put("floor", SiemSeverityFilter.minimumOf(text(input)).orElse(null));
            ArrayNode admitted = answer.putArray("admits");
            for (SecurityEventType type : SecurityEventType.values()) {
                if (SiemSeverityFilter.admits(CefEvent.builder(type, Instant.EPOCH).build(), text(input))) {
                    admitted.add(type.name());
                }
            }
            for (Severity severity : Severity.values()) {
                CefEvent breach = CefEvent.builder(SecurityEventType.SLA_BREACHED, Instant.EPOCH)
                        .issueSeverity(severity).build();
                if (SiemSeverityFilter.admits(breach, text(input))) {
                    admitted.add("SLA_BREACHED/" + severity.name());
                }
            }
        }

        ArrayNode triage = answers.putArray("triage");
        for (JsonNode input : inputs.path("triage")) {
            List<String> previous = new ArrayList<>();
            input.path("previous").forEach(status -> previous.add(text(status)));
            triage.addObject().put("event", TriageSignals.of(previous, text(input.path("result")))
                    .map(Enum::name).orElse(null));
        }

        ReferenceSet.expect("siem/java-answers.json", JSON.writeValueAsString(answers) + "\n");
    }

    /** The event a case describes: built with its calls in order, or through the canonical constructor. */
    private static CefEvent event(JsonNode input) {
        SecurityEventType type = SecurityEventType.valueOf(input.path("type").asText());
        Instant at = Instant.ofEpochSecond(input.path("at").get(0).asLong(), input.path("at").get(1).asLong());
        if (input.has("construct")) {
            return new CefEvent(type, at, null, Map.of(), input.path("construct").asInt());
        }
        CefEvent.Builder builder = CefEvent.builder(type, at);
        if (input.has("issueSeverity")) {
            builder.issueSeverity(Severity.valueOf(input.path("issueSeverity").asText()));
        }
        for (JsonNode call : input.path("calls")) {
            String method = call.get(0).asText();
            String first = text(call.get(1));
            switch (method) {
                case "message" -> builder.message(first);
                case "user" -> builder.user(first);
                case "sourceIp" -> builder.sourceIp(first);
                case "action" -> builder.action(first);
                case "externalId" -> builder.externalId(first);
                case "target" -> builder.target(first);
                case "userAgent" -> builder.userAgent(first);
                case "identifier" -> builder.identifier(first);
                case "component" -> builder.component(first);
                case "extension" -> builder.extension(first, text(call.get(2)));
                default -> throw new IllegalStateException("no builder method " + method);
            }
        }
        return builder.build();
    }

    private static String text(JsonNode node) {
        return node == null || node.isNull() || node.isMissingNode() ? null : node.asText();
    }
}
