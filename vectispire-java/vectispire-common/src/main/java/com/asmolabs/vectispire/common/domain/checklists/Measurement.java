package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Look;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * What a rule found on a project, at one instant: its outcome, why there is no data when there is
 * none, the instant it is as of — the oldest evidence it rests on — and the evidence itself, for each
 * repository the scan or import read, its date and digest, and the figures (decision 0032 §6).
 *
 * <p><b>The evidence is kept as written.</b> {@link #evidenceJson()} is what the measurement's row
 * stores and what its digest covers: the sign-off freezes it with the revision, and an auditor reading
 * next year reads the evidence that was judged, not a recomputation over data that has moved since.
 *
 * @param summary one sentence in English, for the audit entry and a document's evidence column
 */
public record Measurement(
        MeasurementOutcome outcome,
        Optional<NoDataReason> reason,
        Optional<Instant> asOf,
        List<RepositoryEvidence> repositories,
        List<Figure> figures,
        String summary) {

    public Measurement {
        Objects.requireNonNull(outcome, "outcome");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(asOf, "asOf");
        if ((outcome == MeasurementOutcome.NO_DATA) != reason.isPresent()) {
            throw new IllegalArgumentException("A reason is given for no data, and only for no data.");
        }
        repositories = List.copyOf(repositories);
        figures = List.copyOf(figures);
        Objects.requireNonNull(summary, "summary");
    }

    /**
     * What one repository contributed.
     *
     * @param scope the scope's key for a findings rule; empty for a kind that reads one thing
     * @param status {@code examined}, {@code not_applicable}, or the {@link NoDataReason} it lacks data for
     * @param look the scan or import read — for a repository without data, the newest there was, if any
     * @param met whether this repository meets the rule's per-repository conditions; empty when it has
     *     no data or the kind judges the project as a whole
     */
    public record RepositoryEvidence(
            long repositoryId, Optional<String> scope, String status, Optional<Look> look, Optional<Boolean> met,
            Optional<String> detail) {

        public static final String EXAMINED = "examined";
        public static final String NOT_APPLICABLE = "not_applicable";

        public RepositoryEvidence {
            Objects.requireNonNull(scope, "scope");
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(look, "look");
            Objects.requireNonNull(met, "met");
            Objects.requireNonNull(detail, "detail");
        }
    }

    /**
     * A figure over the project: issues of one severity in one scope, open and resolved, settled triage
     * left out of both — or, under the scope {@code all}, the total a threshold was judged on.
     *
     * @param met whether the threshold on this severity is met; empty where none applies or the
     *     measurement has no data to judge it on
     */
    public record Figure(String scope, String severity, long open, long resolved, Optional<Boolean> met,
            Optional<String> detail) {

        public static final String ALL_SCOPES = "all";

        public Figure {
            Objects.requireNonNull(met, "met");
            Objects.requireNonNull(detail, "detail");
        }
    }

    /** The evidence as stored, keys in a fixed order: outcome, reason, as of, repositories, figures. */
    public String evidenceJson() {
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        node.put("outcome", outcome.wireName());
        node.put("reason", reason.map(NoDataReason::wireName).orElse(null));
        node.put("asOf", asOf.map(Instant::toString).orElse(null));
        ArrayNode repositoryNodes = node.putArray("repositories");
        for (RepositoryEvidence repository : repositories) {
            ObjectNode entry = repositoryNodes.addObject();
            entry.put("repositoryId", repository.repositoryId());
            entry.put("scope", repository.scope().orElse(null));
            entry.put("status", repository.status());
            repository.look().ifPresentOrElse(look -> {
                entry.put("source", look.source().wireName());
                entry.put("sourceId", look.id());
                entry.put("at", look.at().toString());
                entry.put("digest", look.digest().orElse(null));
            }, () -> {
                entry.putNull("source");
                entry.putNull("sourceId");
                entry.putNull("at");
                entry.putNull("digest");
            });
            entry.put("met", repository.met().orElse(null));
            entry.put("detail", repository.detail().orElse(null));
        }
        ArrayNode figureNodes = node.putArray("figures");
        for (Figure figure : figures) {
            ObjectNode entry = figureNodes.addObject();
            entry.put("scope", figure.scope());
            entry.put("severity", figure.severity());
            entry.put("open", figure.open());
            entry.put("resolved", figure.resolved());
            entry.put("met", figure.met().orElse(null));
            entry.put("detail", figure.detail().orElse(null));
        }
        node.put("summary", summary);
        try {
            return JSON.writeValueAsString(node);
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("A measurement could not be written.", impossible);
        }
    }

    /** SHA-256 of {@link #evidenceJson()}: two measurements with the same digest judged the same evidence. */
    public String evidenceDigest() {
        return Digests.sha256Hex(evidenceJson());
    }

    /** A stored measurement's evidence read back, as {@link #evidenceJson()} wrote it. */
    public static Measurement read(String evidenceJson) {
        JsonNode node;
        try {
            node = JSON.readTree(evidenceJson);
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("A stored measurement does not read as JSON.", unreadable);
        }
        MeasurementOutcome outcome = MeasurementOutcome.ofStored(node.path("outcome").asText())
                .orElseThrow(() -> new IllegalStateException("A stored measurement has no outcome this version knows."));
        List<RepositoryEvidence> repositories = new ArrayList<>();
        for (JsonNode entry : node.path("repositories")) {
            Optional<Look> look = text(entry, "source").map(source -> new Look(
                    Arrays.stream(MeasurementFacts.Source.values()).filter(value -> value.wireName().equals(source))
                            .findFirst().orElseThrow(() -> new IllegalStateException("Unknown evidence source " + source)),
                    entry.path("sourceId").asLong(), Instant.parse(entry.path("at").asText()), text(entry, "digest")));
            repositories.add(new RepositoryEvidence(entry.path("repositoryId").asLong(), text(entry, "scope"),
                    entry.path("status").asText(), look, bool(entry, "met"), text(entry, "detail")));
        }
        List<Figure> figures = new ArrayList<>();
        for (JsonNode entry : node.path("figures")) {
            figures.add(new Figure(entry.path("scope").asText(), entry.path("severity").asText(),
                    entry.path("open").asLong(), entry.path("resolved").asLong(), bool(entry, "met"),
                    text(entry, "detail")));
        }
        return new Measurement(outcome, text(node, "reason").flatMap(NoDataReason::ofStored),
                text(node, "asOf").map(Instant::parse), repositories, figures, node.path("summary").asText(""));
    }

    private static Optional<String> text(JsonNode node, String name) {
        JsonNode value = node.get(name);
        return value == null || value.isNull() ? Optional.empty() : Optional.of(value.asText());
    }

    private static Optional<Boolean> bool(JsonNode node, String name) {
        JsonNode value = node.get(name);
        return value == null || value.isNull() ? Optional.empty() : Optional.of(value.asBoolean());
    }

    private static final ObjectMapper JSON = new ObjectMapper();
}
