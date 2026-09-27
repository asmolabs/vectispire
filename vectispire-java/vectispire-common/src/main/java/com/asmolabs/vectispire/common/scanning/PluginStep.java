package com.asmolabs.vectispire.common.scanning;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.sarif.SarifFinding;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * What became of one plugin in one scan — <b>three states, not two</b>.
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
    @JsonSubTypes.Type(value = PluginStep.Absent.class, name = "absent")
})
public sealed interface PluginStep {

    String pluginId();

    /** The manifest the executor ran — the task's, which it verified. */
    String manifestDigest();

    /**
     * @param toolName the SARIF {@code tool.driver.name}, provenance only — the plugin id is the
     *     tool's identity
     * @param findings never null: a report whose list is missing is {@link Absent}, see
     *     {@link ScanArtifacts}
     */
    record Produced(String pluginId, String manifestDigest, String toolName, String toolVersion,
            List<SarifFinding> findings) implements PluginStep {}

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
}
