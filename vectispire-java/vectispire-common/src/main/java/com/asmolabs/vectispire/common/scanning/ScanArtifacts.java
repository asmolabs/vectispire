package com.asmolabs.vectispire.common.scanning;

import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.scanning.scanners.DependencyScanner.DependencyFinding;
import com.asmolabs.vectispire.common.scanning.scanners.IacScanner.IacFinding;
import com.asmolabs.vectispire.common.scanning.scanners.SastScanner.SastFinding;
import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner.SecretFinding;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * What a scan produced.
 *
 * <p><b>Absent means "the step did not run"; an empty list means "found nothing".</b> That
 * distinction decides the fate of the backlog for each finding type, and it is why every result
 * is an {@link Optional} rather than a list that defaults to empty (decision 0007).
 */
public record ScanArtifacts(
        Optional<JsonNode> sbom,
        Optional<ProjectManifest.Project> project,
        // **The languages the tree is written in, as the census names them** — the wire names of
        // `Language`, the vocabulary a plugin manifest declares. Absent when no census was taken or
        // it stopped before the end of the tree (an image, a walk past its bounds, an agent older
        // than the field): "we do not know", which must never read as the empty set, "the census
        // saw every file and none says a language" (decision 0007). Strings rather than
        // `Language`, whose reader refuses a name it does not know: a newer executor naming a
        // language this control plane has never heard of would otherwise fail the whole result, its
        // findings with it. The name is dropped when written instead (`DetectedLanguages`).
        Optional<Set<String>> languages,
        Optional<List<DependencyFinding>> dependencies,
        Optional<List<SecretFinding>> secrets,
        Optional<List<IacFinding>> iac,
        Optional<List<SastFinding>> sast,
        Optional<List<ApiEndpoint>> apiEndpoints,
        Optional<List<ApiContract>> apiContracts,
        // A list of three-state results rather than an Optional: see PluginStep for why a plugin
        // needs "not applicable" beside "ran" and "did not run". Empty means no plugin was asked
        // for — or an agent older than plugins, which reports none; neither resolves anything.
        List<PluginStep> plugins,
        List<Failure> failures,
        // **ISO-8601 text, pinned here and not in either mapper.** The published contract says
        // `string, format: duration`; Jackson writes a `Duration` as a decimal number of seconds
        // unless told otherwise, and `WRITE_DATES_AS_TIMESTAMPS`, which both sides disable, does
        // not govern durations. On the record, the two ends of the protocol cannot disagree
        // whatever their mappers say. Reading stays lenient: a number from an older agent is still
        // accepted as seconds.
        @JsonFormat(shape = JsonFormat.Shape.STRING) Duration duration) {

    /**
     * Every way a document can say "not produced" reads as absent.
     *
     * <p><b>The SBOM is the one that needed it.</b> An agent that produced none writes
     * {@code "sbom": null}, and Jackson reads a JSON null into a {@code JsonNode} as a
     * {@code NullNode} — a present value — so {@code Optional.of(NullNode)} arrived where
     * {@code Optional.empty()} was sent. The other fields are defended for the same reason in the
     * other direction: a field missing from an older agent's body must mean "did not look", never a
     * null that the ingestor dereferences. Absent is the safe reading; it resolves nothing.
     */
    public ScanArtifacts {
        sbom = sbom == null ? Optional.empty() : sbom.filter(node -> !node.isNull() && !node.isMissingNode());
        project = project == null ? Optional.empty() : project;
        languages = languages == null ? Optional.empty() : languages.map(names -> names.stream()
                .filter(java.util.Objects::nonNull)
                .collect(java.util.stream.Collectors.toUnmodifiableSet()));
        dependencies = dependencies == null ? Optional.empty() : dependencies;
        secrets = secrets == null ? Optional.empty() : secrets;
        iac = iac == null ? Optional.empty() : iac;
        sast = sast == null ? Optional.empty() : sast;
        apiEndpoints = apiEndpoints == null ? Optional.empty() : apiEndpoints;
        apiContracts = apiContracts == null ? Optional.empty() : apiContracts;
        plugins = plugins == null ? List.of() : plugins.stream()
                .filter(java.util.Objects::nonNull)
                .map(ScanArtifacts::withoutMissingFindings)
                .toList();
        failures = failures == null ? List.of() : failures;
    }

    /**
     * A {@code produced} step whose findings did not arrive is absent, never empty.
     *
     * <p>{@code "findings": null} — or no field at all, from a body somebody wrote by hand — would
     * otherwise reach ingestion as a plugin that ran and found nothing, which resolves its whole
     * backlog on the target. The same defence as the {@code NullNode} SBOM above, for the same
     * reason: absent is the reading that resolves nothing.
     */
    private static PluginStep withoutMissingFindings(PluginStep step) {
        if (step instanceof PluginStep.Produced produced && produced.findings() == null) {
            return new PluginStep.Absent(produced.pluginId(), produced.manifestDigest(),
                    "the executor reported the plugin as run without a list of findings");
        }
        return step;
    }

    /** @param step named as an operator would recognize it, not as the class is called */
    public record Failure(String step, String reason) {}

    /**
     * Whether no analysis produced anything. A plugin that ran counts as an observation; one that
     * was not applicable does not — it looked at nothing.
     */
    public boolean observedNothing() {
        return dependencies.isEmpty() && secrets.isEmpty() && iac.isEmpty() && sast.isEmpty()
                && plugins.stream().noneMatch(PluginStep.Produced.class::isInstance);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private JsonNode sbom;
        private ProjectManifest.Project project;
        private Set<String> languages;
        private List<DependencyFinding> dependencies;
        private List<SecretFinding> secrets;
        private List<IacFinding> iac;
        private List<SastFinding> sast;
        private List<ApiEndpoint> apiEndpoints;
        private List<ApiContract> apiContracts;
        private final List<PluginStep> plugins = new ArrayList<>();
        private final List<Failure> failures = new ArrayList<>();

        public Builder sbom(JsonNode value) { this.sbom = value; return this; }
        public Builder project(ProjectManifest.Project value) { this.project = value; return this; }
        public Builder languages(Set<Language> value) {
            this.languages = value == null ? null : value.stream().map(Language::wireName).collect(
                    java.util.stream.Collectors.toUnmodifiableSet());
            return this;
        }
        public Builder dependencies(List<DependencyFinding> value) { this.dependencies = value; return this; }
        public Builder secrets(List<SecretFinding> value) { this.secrets = value; return this; }
        public Builder iac(List<IacFinding> value) { this.iac = value; return this; }
        public Builder sast(List<SastFinding> value) { this.sast = value; return this; }
        public Builder apiEndpoints(List<ApiEndpoint> value) { this.apiEndpoints = value; return this; }
        public Builder apiContracts(List<ApiContract> value) { this.apiContracts = value; return this; }
        public Builder plugin(PluginStep value) { this.plugins.add(value); return this; }

        public Builder failed(String step, String reason) {
            failures.add(new Failure(step, reason));
            return this;
        }

        public ScanArtifacts build(Duration duration) {
            return new ScanArtifacts(
                    Optional.ofNullable(sbom),
                    Optional.ofNullable(project),
                    Optional.ofNullable(languages),
                    Optional.ofNullable(dependencies),
                    Optional.ofNullable(secrets),
                    Optional.ofNullable(iac),
                    Optional.ofNullable(sast),
                    Optional.ofNullable(apiEndpoints),
                    Optional.ofNullable(apiContracts),
                    List.copyOf(plugins),
                    List.copyOf(failures),
                    duration);
        }
    }
}
