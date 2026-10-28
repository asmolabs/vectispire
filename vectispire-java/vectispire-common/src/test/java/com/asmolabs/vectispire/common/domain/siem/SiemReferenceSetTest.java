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
 * {@code isBlank} and {@code trim}, an IPv4-mapped address in brackets, a full-width digit in a port; and for the
 * collector CA, BouncyCastle's reading of the PEM text and of the certificates in {@code siem/collector-ca/}
 * ({@code generate.jsh}), the subject as {@code X500Name} renders it, and every refusal's sentence.
 *
 * <p>A webhook's port is checked as {@code URI.getPort} reads it; a syslog host of digits and dots as
 * {@code Inet4Address.ofLiteral} reads it after one trailing dot — its short forms, its bounds per form, its
 * fifteen-character limit; a port's leading zeros are kept. A bundle is answered three ways: {@code read} and
 * {@code parse}, which a stored bundle goes through and which stop at a {@code -----BEGIN} line they cannot read,
 * and {@code parsePasted}, which a typed one goes through and which refuses it.
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

        JsonNode ca = inputs.path("collectorCa");
        Instant now = Instant.ofEpochSecond(ca.path("now").get(0).asLong(), ca.path("now").get(1).asLong());
        ArrayNode collectorCa = answers.putArray("collectorCa");
        for (JsonNode input : ca.path("cases")) {
            String pem = bundle(input);
            ObjectNode answer = collectorCa.addObject().put("name", input.path("name").asText());
            try {
                CollectorCa read = CollectorCa.read(pem);
                ObjectNode described = answer.putObject("read")
                        .put("pemSha256", sha256(read.pem().getBytes(StandardCharsets.UTF_8)))
                        .put("subject", read.subject())
                        .put("notAfter", read.notAfter().toString());
                ArrayNode anchors = described.putArray("anchors");
                for (CollectorCa.Anchor anchor : read.anchors()) {
                    anchors.addObject()
                            .put("subject", anchor.subject())
                            .put("notBefore", anchor.notBefore().toString())
                            .put("notAfter", anchor.notAfter().toString())
                            .put("derSha256", sha256(anchor.der()));
                }
            } catch (IllegalArgumentException refused) {
                answer.put("readRefused", refused.getMessage());
            }
            try {
                CollectorCa.parse(pem, now);
                answer.put("parse", "accepted");
            } catch (IllegalArgumentException refused) {
                answer.put("parse", refused.getMessage());
            }
            try {
                CollectorCa.parsePasted(pem, now);
                answer.put("parsePasted", "accepted");
            } catch (IllegalArgumentException refused) {
                answer.put("parsePasted", refused.getMessage());
            }
        }

        ReferenceSet.expect("siem/java-answers.json", JSON.writeValueAsString(answers) + "\n");
    }

    /**
     * A case's text: its parts joined — a fixture of {@code siem/collector-ca/}, repeated and with every
     * occurrence of one string replaced when the case says so, or a text as written — or {@code null}.
     */
    private static String bundle(JsonNode input) {
        if (input.path("absent").asBoolean()) {
            return null;
        }
        StringBuilder text = new StringBuilder();
        for (JsonNode part : input.path("parts")) {
            if (part.has("text")) {
                text.append(part.path("text").asText());
                continue;
            }
            String fixture = ReferenceSet.read("siem/collector-ca/" + part.path("file").asText());
            if (part.has("replace")) {
                fixture = fixture.replace(part.path("replace").get(0).asText(), part.path("replace").get(1).asText());
            }
            text.append(fixture.repeat(part.path("repeat").asInt(1)));
        }
        return text.toString();
    }

    private static String sha256(byte[] bytes) throws Exception {
        return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
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
