package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.scanning.PluginStep;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * What became of one plugin in one scan, as the scan keeps it: the state, and what the state needs to
 * be read — how many findings, which languages were missing, why it failed.
 *
 * <p><b>Kept on the scan, because "not applicable" is a report, not a silence.</b> The third state
 * leaves the backlog alone like a failure does, and says the opposite about the plugin: nothing is
 * broken, there was nothing for it to read. An absent plugin is also in the scan's failures, under
 * {@code plugin <id>}; a not-applicable one is nowhere else, so without this record a screen could not
 * tell "the Java plugin skipped a Python repository" from "the Java plugin was never asked".
 *
 * <p>The findings themselves are the scan's findings rows; only their count is kept here.
 *
 * <p><b>A refused plugin is kept as refused</b>, beside absent: the executor would not start it for
 * want of a verified signer (decision 0017 §9.1). Both leave the backlog alone and are in the scan's
 * failures; only the state tells "its image is not signed" from "it crashed", and the checklist's
 * measurement names the one it was.
 *
 * @param state {@code produced}, {@code not_applicable}, {@code absent} or {@code refused} — {@link
 *     State} — the wire's discriminator
 * @param findings for a produced plugin, how many results it reported; {@code null} otherwise
 * @param languages for a not-applicable plugin, the languages it declares and the tree lacked
 * @param reason for an absent or refused plugin, what went wrong, in the executor's words
 * @param refusal for a refused plugin, {@code unsigned} or {@code signature_unverified} — {@link
 *     PluginStep.Refusal}; null otherwise, and for a reason this version does not know
 * @param signature for a produced plugin, what the executor established about the image's signer:
 *     {@code verified}, {@code waived} — it ran unsigned under the governor's waiver — or {@code
 *     not_required}, the executor's operator having switched the requirement off; null for a scan
 *     from before the field
 */
public record PluginOutcome(
        String pluginId,
        String manifestDigest,
        String state,
        Integer findings,
        List<String> languages,
        String reason,
        String refusal,
        String signature) {

    /**
     * Decision 0017's three states and the refusal, as {@code state} spells them. The component stays a string, so a
     * state a later version writes is still read back — and read as absent by whoever decides on it —
     * rather than failing the whole scan's list; this type is what the code and the OpenAPI document
     * ({@link ScanVocabularies}) take the tokens from.
     */
    public enum State {
        PRODUCED("produced"),
        NOT_APPLICABLE("not_applicable"),
        ABSENT("absent"),
        REFUSED("refused");

        private final String wireName;

        State(String wireName) {
            this.wireName = wireName;
        }

        public String wireName() {
            return wireName;
        }

        /** Empty for a state this version does not know, and for none. */
        public static Optional<State> fromWire(String value) {
            return Arrays.stream(values()).filter(state -> state.wireName.equals(value)).findFirst();
        }
    }

    private static final ObjectMapper JSON =
            new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    public static PluginOutcome of(PluginStep step) {
        return switch (step) {
            case PluginStep.Produced produced -> new PluginOutcome(
                    produced.pluginId(), produced.manifestDigest(), State.PRODUCED.wireName(), produced.findings().size(),
                    List.of(), null, null, produced.signature() == null ? null : produced.signature().wireName());
            case PluginStep.NotApplicable skipped -> new PluginOutcome(
                    skipped.pluginId(), skipped.manifestDigest(), State.NOT_APPLICABLE.wireName(), null,
                    skipped.languages().stream().map(Language::wireName).toList(), null, null, null);
            case PluginStep.Absent absent -> new PluginOutcome(
                    absent.pluginId(), absent.manifestDigest(), State.ABSENT.wireName(), null, List.of(), absent.reason(),
                    null, null);
            case PluginStep.Refused refused -> new PluginOutcome(
                    refused.pluginId(), refused.manifestDigest(), State.REFUSED.wireName(), null, List.of(),
                    refused.reason(), refused.refusal() == null ? null : refused.refusal().wireName(), null);
        };
    }

    /** The scan's column: a JSON array, or {@code null} for a scan that ran no plugin. */
    static String write(List<PluginStep> steps) {
        if (steps == null || steps.isEmpty()) {
            return null;
        }
        try {
            return JSON.writeValueAsString(steps.stream().map(PluginOutcome::of).toList());
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("A plugin outcome could not be written.", impossible);
        }
    }

    /**
     * The column read back; an unreadable one reads as no outcome rather than failing the scan's
     * page — the findings and the failures are still there, and they are what decides anything.
     */
    static List<PluginOutcome> read(String column) {
        if (column == null || column.isBlank()) {
            return List.of();
        }
        try {
            return List.copyOf(JSON.readValue(column, new TypeReference<List<PluginOutcome>>() {}));
        } catch (JsonProcessingException unreadable) {
            return List.of();
        }
    }
}
