package com.asmolabs.vectispire.common.domain.exports;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * A SARIF 2.1.0 log, as records.
 *
 * <p>SARIF exists so a finding stops living only inside Vectispire. It is what GitHub code
 * scanning, GitLab and Azure DevOps ingest natively, and therefore what puts an issue in
 * front of the person who introduced it — annotated on the line, in the merge request —
 * instead of on a dashboard they have no reason to open.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SarifLog(@JsonProperty("$schema") String schema, String version, List<Run> runs) {

    public static final String VERSION = "2.1.0";
    public static final String SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

    public record Run(Tool tool, List<Result> results, Map<String, Object> properties) {}

    public record Tool(Driver driver) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Driver(String name, String version, String informationUri, List<Rule> rules) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Rule(
            String id,
            String name,
            Text shortDescription,
            Text fullDescription,
            String helpUri,
            Map<String, Object> properties) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Result(
            String ruleId,
            int ruleIndex,
            String level,
            Text message,
            List<Location> locations,
            Map<String, String> partialFingerprints,
            Map<String, Object> properties,
            List<Suppression> suppressions) {}

    public record Text(String text) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Location(PhysicalLocation physicalLocation, List<LogicalLocation> logicalLocations) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PhysicalLocation(ArtifactLocation artifactLocation, Region region) {}

    public record ArtifactLocation(String uri) {}

    public record Region(int startLine) {}

    public record LogicalLocation(String name, String kind) {}

    /**
     * @param kind {@code external} — the decision was taken in Vectispire, not in a source
     *     annotation, which is what that kind documents
     */
    public record Suppression(String kind, String justification) {}
}
