package com.asmolabs.zanshin.common.scanning;

import com.asmolabs.zanshin.common.scanning.scanners.DependencyScanner.DependencyFinding;
import com.asmolabs.zanshin.common.scanning.scanners.IacScanner.IacFinding;
import com.asmolabs.zanshin.common.scanning.scanners.SastScanner.SastFinding;
import com.asmolabs.zanshin.common.scanning.scanners.SecretsScanner.SecretFinding;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * What a scan produced.
 *
 * <p><b>Absent means "the step did not run"; an empty list means "found nothing".</b> That
 * distinction decides the fate of the backlog for each finding type, and it is why every result
 * is an {@link Optional} rather than a list that defaults to empty (decision 0007).
 *
 * <p>{@code Optional} in a field is usually a smell. Here it is the point: the whole class
 * exists to keep two states apart that a nullable list lets a caller confuse, and a caller who
 * writes {@code artifacts.secrets().orElse(List.of())} has to type the mistake out.
 *
 * @param failures what went wrong, so an operator knows what they are not seeing
 */
public record ScanArtifacts(
        Optional<JsonNode> sbom,
        Optional<List<DependencyFinding>> dependencies,
        Optional<List<SecretFinding>> secrets,
        Optional<List<IacFinding>> iac,
        Optional<List<SastFinding>> sast,
        List<Failure> failures,
        Duration duration) {

    /** @param step named as an operator would recognize it, not as the class is called */
    public record Failure(String step, String reason) {}

    /** Nothing looked at yet. Every step absent, which is the honest starting point. */
    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private JsonNode sbom;
        private List<DependencyFinding> dependencies;
        private List<SecretFinding> secrets;
        private List<IacFinding> iac;
        private List<SastFinding> sast;
        private final List<Failure> failures = new ArrayList<>();

        public Builder sbom(JsonNode value) { this.sbom = value; return this; }
        public Builder dependencies(List<DependencyFinding> value) { this.dependencies = value; return this; }
        public Builder secrets(List<SecretFinding> value) { this.secrets = value; return this; }
        public Builder iac(List<IacFinding> value) { this.iac = value; return this; }
        public Builder sast(List<SastFinding> value) { this.sast = value; return this; }

        public Builder failed(String step, String reason) {
            failures.add(new Failure(step, reason));
            return this;
        }

        public ScanArtifacts build(Duration duration) {
            return new ScanArtifacts(
                    Optional.ofNullable(sbom),
                    Optional.ofNullable(dependencies),
                    Optional.ofNullable(secrets),
                    Optional.ofNullable(iac),
                    Optional.ofNullable(sast),
                    List.copyOf(failures),
                    duration);
        }
    }
}
