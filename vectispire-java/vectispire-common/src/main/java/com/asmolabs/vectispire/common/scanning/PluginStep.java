package com.asmolabs.vectispire.common.scanning;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.sarif.SarifFinding;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * What became of one plugin in one scan — <b>three states, not two</b>, and a fourth for the executor
 * that would not start it.
 *
 * <p>Every other step of a scan is an {@code Optional}: present means "ran" (an empty list resolves
 * the backlog), absent means "did not run" (the backlog is left alone and a failure is reported). A
 * plugin needs a third answer. A Java plugin on a Python repository did not fail and did not find
 * nothing: it had nothing to look at. Reporting it empty would resolve every issue it ever opened on
 * that target the day its Java was removed — and then reopen them, triage cleared, when a Java file
 * came back. Reporting it absent would put a failure on every scan of every repository not written
 * in its languages, until nobody read the failures any more.
 *
 * <ul>
 *   <li>{@link Produced} — the plugin ran and its report was read. Its findings, possibly none:
 *       <b>none resolves this plugin's open issues on the target</b>, and only this plugin's.
 *   <li>{@link NotApplicable} — none of its languages is in the tree. Its issues are left as they
 *       are, like absent; the scan says "not applicable", not "failed".
 *   <li>{@link Absent} — it should have run and did not produce a usable report: fetched no
 *       definition, exited on an undeclared code, wrote no report, wrote one that was refused, or
 *       said it computed no result. Its issues are left as they are and the reason is a failure of
 *       the scan (decision 0007).
 *   <li>{@link Refused} — the executor would not start it: its manifest declares no signer where one
 *       is required and no waiver covers it, or the signer it declares did not verify the image. Its
 *       issues are left as they are and it is a failure of the scan, like absent; told apart from
 *       absent because the fix is not the plugin's code but its provenance — sign the image, or have
 *       the governor waive the requirement for it, in writing (decision 0017 §9.1). Never folded into
 *       absent: "unsigned" read as "crashed" is how a requirement nobody can see gets switched off.
 * </ul>
 *
 * <p><b>A plugin missing from the list is absent</b>, whatever the task asked: an agent older than
 * plugins ignores the field and reports nothing, and nothing must be read into that.
 *
 * <p>The discriminator is part of the agent protocol, spelled out for the reason {@code
 * ScanTask.Target} gives: a sealed type tells a JSON parser nothing.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "state")
@JsonSubTypes({
    @JsonSubTypes.Type(value = PluginStep.Produced.class, name = "produced"),
    @JsonSubTypes.Type(value = PluginStep.NotApplicable.class, name = "not_applicable"),
    @JsonSubTypes.Type(value = PluginStep.Absent.class, name = "absent"),
    @JsonSubTypes.Type(value = PluginStep.Refused.class, name = "refused")
})
public sealed interface PluginStep {

    String pluginId();

    /** The manifest the executor ran — the task's, which it verified. */
    String manifestDigest();

    /**
     * What the executor established about who built the image it ran — kept with a produced step so a
     * plugin that ran unsigned says so in every scan it ran in, not only in the registry.
     */
    enum Signature {
        /** The manifest declares a signer, and cosign verified the image against it before the pull. */
        VERIFIED("verified"),
        /**
         * The manifest declares none, the executor requires one, and the governor's waiver for this
         * plugin let it run — the waiver the task carried ({@code PluginRef#runsUnsigned}).
         */
        WAIVED("waived"),
        /** The manifest declares none and the executor does not require one: its operator switched it off. */
        NOT_REQUIRED("not_required");

        private final String wireName;

        Signature(String wireName) {
            this.wireName = wireName;
        }

        @JsonValue
        public String wireName() {
            return wireName;
        }

        /** Null for a token this version does not know — the step it travels in is still read. */
        @JsonCreator
        public static Signature fromWire(String value) {
            return Arrays.stream(values()).filter(signature -> signature.wireName.equals(value)).findFirst().orElse(null);
        }
    }

    /** Why an executor would not start a plugin. */
    enum Refusal {
        /** Its manifest declares no signer, this executor requires one, and no waiver covers the plugin. */
        UNSIGNED("unsigned"),
        /**
         * Its manifest declares a signer and cosign did not verify the image against it — another
         * signer, no signature, or a registry or trust root that could not be reached: an image nobody
         * verified is not run, whatever the reason. A waiver never covers this: it lifts the requirement
         * to declare a signer, not the verification of one declared.
         */
        SIGNATURE_UNVERIFIED("signature_unverified");

        private final String wireName;

        Refusal(String wireName) {
            this.wireName = wireName;
        }

        @JsonValue
        public String wireName() {
            return wireName;
        }

        /** Null for a token this version does not know: still a refusal, with its detail. */
        @JsonCreator
        public static Refusal fromWire(String value) {
            return Arrays.stream(values()).filter(refusal -> refusal.wireName.equals(value)).findFirst().orElse(null);
        }
    }

    /**
     * @param toolName the SARIF {@code tool.driver.name}, provenance only — the plugin id is the
     *     tool's identity
     * @param findings never null: a report whose list is missing is {@link Absent}, see
     *     {@link ScanArtifacts}
     * @param signature what the executor established about the image's signer; null from an executor
     *     older than the field, which says nothing either way
     */
    record Produced(String pluginId, String manifestDigest, String toolName, String toolVersion,
            List<SarifFinding> findings, Signature signature) implements PluginStep {

        public Produced(String pluginId, String manifestDigest, String toolName, String toolVersion,
                List<SarifFinding> findings) {
            this(pluginId, manifestDigest, toolName, toolVersion, findings, null);
        }
    }

    /** @param languages what the plugin declares, none of which the census found */
    record NotApplicable(String pluginId, String manifestDigest, Set<Language> languages) implements PluginStep {

        public NotApplicable {
            languages = languages == null || languages.isEmpty()
                    ? Set.of()
                    : Collections.unmodifiableSet(EnumSet.copyOf(languages));
        }
    }

    /** @param reason what an operator reads in the scan's failures */
    record Absent(String pluginId, String manifestDigest, String reason) implements PluginStep {}

    /**
     * @param refusal why it was not started; null for a reason a newer executor names and this version
     *     does not know — still a refusal, never read as having run
     * @param reason what an operator reads in the scan's failures, cosign's own words included
     */
    record Refused(String pluginId, String manifestDigest, Refusal refusal, String reason) implements PluginStep {}
}
