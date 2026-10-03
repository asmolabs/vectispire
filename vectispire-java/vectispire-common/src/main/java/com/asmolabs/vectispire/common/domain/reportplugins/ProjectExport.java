package com.asmolabs.vectispire.common.domain.reportplugins;

import com.asmolabs.vectispire.common.domain.checklists.ChecklistStatement;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * One project as Vectispire knows it, for whoever renders it into a document of their own — the
 * {@code vectispire-project-export} document of decision 0035 §1, the only thing a report plugin receives.
 *
 * <p><b>A contract, not a view.</b> Its shape is the published JSON Schema's ({@link ProjectExportSchema}),
 * held to it by a test that validates every export the suite builds and pins the schema's digest. A
 * minor adds an optional field and never removes or changes one; anything else is a new major and a new
 * schema file. The API's views follow the screens; this follows the schema.
 *
 * <p><b>Every part is present, an empty list meaning "produced, nothing in it"</b> (decision 0007). A
 * value nobody recorded is {@code null}, never a placeholder: a renderer that prints "0" for a scan that
 * never ran, or a verdict for a target the gate never judged, would put that under the platform's
 * signature.
 *
 * <p><b>What is deliberately absent</b> — and must stay so, whatever a renderer would like: source code
 * and anything quoted from it, the matched value of a secret, the exchanges of a model review,
 * credentials of any kind, the bytes of an evidence file (named by its SHA-256 only), an account's e-mail
 * address, role, team or grants, the audit log, other projects, and the portfolio's posture figures.
 * People appear as an account id and a display name, nothing else.
 *
 * @param schema always {@value ProjectExportSchema#NAME}
 * @param schemaVersion {@code MAJOR.MINOR}
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonPropertyOrder({"schema", "schema_version", "export", "project", "scans", "gate", "issues", "issue_counts",
        "inventory", "compliance", "checklists"})
public record ProjectExport(
        String schema,
        String schemaVersion,
        About export,
        Project project,
        List<TargetScan> scans,
        List<TargetVerdict> gate,
        List<Issue> issues,
        List<IssueCount> issueCounts,
        Inventory inventory,
        Compliance compliance,
        List<Checklist> checklists) {

    public ProjectExport {
        Objects.requireNonNull(export, "export");
        Objects.requireNonNull(project, "project");
        scans = List.copyOf(scans);
        gate = List.copyOf(gate);
        issues = List.copyOf(issues);
        issueCounts = List.copyOf(issueCounts);
        Objects.requireNonNull(inventory, "inventory");
        Objects.requireNonNull(compliance, "compliance");
        checklists = List.copyOf(checklists);
    }

    /** The current version's export: {@code schema} and {@code schema_version} are not the builder's to choose. */
    public static ProjectExport of(About export, Project project, List<TargetScan> scans, List<TargetVerdict> gate,
            List<Issue> issues, List<IssueCount> issueCounts, Inventory inventory, Compliance compliance,
            List<Checklist> checklists) {
        return new ProjectExport(ProjectExportSchema.NAME, ProjectExportSchema.VERSION, export, project, scans, gate,
                issues, issueCounts, inventory, compliance, checklists);
    }

    /**
     * The export itself: when, by which product, for whom.
     *
     * @param productVersion the Vectispire version that built it; null when the build states none
     * @param locale the requester's preferred language, as a BCP 47 tag, when the request stated one
     */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record About(
            String id, Instant generatedAt, String productVersion, Person requester, String locale,
            Installation installation) {}

    /**
     * A person, as every document may name one: the account and its display name.
     *
     * <p><b>Never the e-mail address, nor the user name</b> — an identity provider's user name is often the
     * address itself. {@code displayName} is null where the account has none, or where the stored name no
     * longer resolves to an account; {@code accountId} is null in the second case.
     */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Person(Long accountId, String displayName) {}

    /** @param publicUrl where this installation says it is reachable; null when it does not say */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Installation(String name, String publicUrl) {}

    /** A repository or an image, by kind and id: what every per-target part is keyed by. */
    public record Target(String kind, long id) {

        public static final String REPOSITORY = "repository";
        public static final String CONTAINER = "container";
    }

    /** @param repositories then {@code containers}: every target filed in the project, ascending by id */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Project(
            long id, String name, String description, Instant createdAt, Solution solution,
            List<Repository> repositories, List<Container> containers) {

        public Project {
            repositories = List.copyOf(repositories);
            containers = List.copyOf(containers);
        }
    }

    public record Solution(long id, String name) {}

    /** @param url as every screen shows it: a credential the stored URL carries is masked, never written */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Repository(long id, String name, String url, String branch, String subPath) {}

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Container(long id, String registry, String image, String tag) {}

    /** @param scan the target's newest completed scan; null when it has none */
    public record TargetScan(Target target, Scan scan) {}

    /**
     * @param queuedAt when the scan was queued — the instant every screen dates a scan by
     * @param examinedTypes the built-in finding types whose step produced; null where the scan did not
     *     record it, which is not the empty list, "recorded, and none produced"
     * @param failures each failed step, as {@code step: reason}; empty when none failed
     * @param plugins each plugin's state in this scan (decision 0017 §4)
     */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Scan(
            long id, Instant queuedAt, Long durationMs, List<String> examinedTypes, List<String> failures,
            List<PluginStep> plugins) {

        public Scan {
            examinedTypes = examinedTypes == null ? null : List.copyOf(examinedTypes);
            failures = List.copyOf(failures);
            plugins = List.copyOf(plugins);
        }
    }

    /** @param state {@code produced}, {@code not_applicable}, {@code absent} or {@code refused} — open */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record PluginStep(
            String pluginId, String manifestDigest, String state, Integer findings, List<String> languages,
            String reason, String refusal, String signature) {

        public PluginStep {
            languages = languages == null ? List.of() : List.copyOf(languages);
        }
    }

    /** @param verdict the last verdict the gate recorded for the target; null when it never judged it */
    public record TargetVerdict(Target target, Verdict verdict) {}

    /**
     * One verdict of the gate's register, as recorded. The register keeps counts, not the reasons one by
     * one: what is here is what it kept.
     *
     * @param policySource where the policy that judged came from, as the register names it
     */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Verdict(
            boolean passed, Instant decidedAt, String failOnSeverity, String policySource, Long policyVersion,
            boolean relaxationsIgnored, int evaluated, int violations, long critical, long high, long medium,
            long low) {}

    /**
     * An issue that is not resolved.
     *
     * @param identifier the advisory id of a vulnerability, the rule of anything else
     * @param title the advisory's text, for the types whose text is an advisory's or a catalogue's —
     *     vulnerabilities, licences, end of life. Null for every other type: a tool's message may quote the
     *     code it matched, and a secret's the secret itself
     * @param tool the tool key of a plugin's or an import's finding ({@code plugin:<id>},
     *     {@code import:<source>/<tool>}), or the built-in tool's name; null where none was recorded
     * @param remediation where the issue stands against its remediation deadline; null where none applies
     */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Issue(
            long id, Target target, String type, String severity, String identifier, String title, String tool,
            Component component, String path, Integer line, Instant firstSeenAt, Instant lastSeenAt, String state,
            boolean kev, Double epss, Double cvss, String fixVersions, Triage triage, Remediation remediation) {}

    /** The package an issue is about; null on the issue when it names none. */
    public record Component(String name, String version, String purl) {}

    /**
     * The triage decision an issue carries; null on the issue when nobody recorded one — a new issue is
     * under review by default, with nobody named, and that is no decision.
     *
     * @param reviewAt when an accepted decision is to be looked at again; null when it is not
     */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Triage(
            String status, String justification, String comment, Person decidedBy, Instant decidedAt,
            Instant reviewAt) {}

    /** @param state {@code on_time}, {@code due_soon} or {@code overdue} — open */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Remediation(Instant dueAt, String state) {}

    /**
     * How many issues of the project's targets are in one state — the resolved ones included, which are
     * counted here and not listed.
     *
     * @param triageStatus as recorded — {@code under_review} for an issue nobody has decided yet
     */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record IssueCount(String type, String severity, String state, String triageStatus, long count) {}

    /**
     * The project's consolidated components: the newest completed scan of each target, merged.
     *
     * @param complete every target's inventory is known; false when one was never scanned or its newest
     *     scan holds no inventory, and the components then do not speak for it
     */
    public record Inventory(boolean complete, List<InventoryTarget> targets, List<InventoryComponent> components) {

        public Inventory {
            targets = List.copyOf(targets);
            components = List.copyOf(components);
        }
    }

    /** @param state {@code listed}, {@code empty}, {@code absent} or {@code never_scanned} — open */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record InventoryTarget(Target target, Long scanId, String state, int componentCount) {}

    /** @param purl null where the SBOM gave none */
    public record InventoryComponent(String name, String version, String purl, String type, List<Target> targets) {

        public InventoryComponent {
            targets = List.copyOf(targets);
        }
    }

    /**
     * The project's compliance state, computed over its targets as its compliance screen computes it.
     *
     * @param observedTargets how many of the monitored targets were ever scanned, and {@code freshTargets}
     *     how many within the freshness window: the verdicts are capped by both
     */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Compliance(
            int monitoredTargets, int observedTargets, int freshTargets, List<Framework> frameworks) {

        public Compliance {
            frameworks = List.copyOf(frameworks);
        }
    }

    /** @param status {@code COMPLIANT}, {@code PARTIAL}, {@code NON_COMPLIANT} or {@code NO_DATA} — open */
    public record Framework(String id, String title, String status, int score, List<Control> controls) {

        public Framework {
            controls = List.copyOf(controls);
        }
    }

    /** @param score zero wherever the status is {@code NO_DATA}: read the status first */
    public record Control(String id, String name, String category, String status, int score, String details) {}

    /**
     * A checklist revision's statement — {@code checklist.json} of decision 0032 §10, in its own form.
     *
     * <p><b>The statement's people are named by display name.</b> The signed package keeps the names the
     * accounts had when they acted; here each is the account's display name, or null, by the rule of
     * {@link Person}. {@code documentSha256} names the signed package, whose own statement is the one under
     * the signature.
     *
     * @param draft the project's open revision, not signed off; false for a signed-off one
     * @param documentSha256 the SHA-256 of the package signed at the sign-off; null for a draft
     */
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Checklist(boolean draft, String documentSha256, ChecklistStatement statement) {}
}
