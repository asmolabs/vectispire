package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.compliance.ComplianceControl;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEngine;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEngine.PasswordAccounts;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEngine.PlatformPosture;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEngine.PostureInput;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEvaluation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceHistory;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceSnapshot;
import com.asmolabs.vectispire.common.domain.compliance.EvidenceBundleManifest;
import com.asmolabs.vectispire.common.domain.compliance.ScopeCoverage;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Applicability;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Declaration;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.EvidenceSource;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Implementation;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.exports.SpreadsheetCells;
import com.asmolabs.vectispire.common.domain.gate.Observation;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.owasp.CoverageWeek;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.CoverageLine;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.CoverageReason;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Evidence;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Gap;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.GapCount;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Grid;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Measurement;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.ReasonCode;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Split;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.State;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCwe;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.trends.MttrCalculator;
import com.asmolabs.vectispire.core.RustReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * The pure compliance domain the Rust port ({@code vectispire-domain}'s {@code compliance}, {@code owasp_coverage},
 * {@code owasp_cwe}, {@code mttr} and {@code spreadsheet_cells}) is held to, written to
 * {@code vectispire-rust/reference/compliance/} before that port: the six frameworks and how a path segment names
 * one, the engine's verdicts over a grid of estates and platforms, the declaration of applicability set against
 * them, the attributed history, the scope's gap, the bundle's manifest, the OWASP grid over every scope of the
 * kinds of evidence there are, the CWE lists, the coverage week, the MTTR and the spreadsheet neutralisation.
 *
 * <p><b>The records' shapes are the evidence bundle's.</b> Where a record is written whole it goes through the
 * mapper {@code EvidenceVaultService} writes the bundle with — the JavaTimeModule, dates as text — so the field names,
 * their order and the nulls are those an archive carries.
 *
 * <p><b>Texts are written once.</b> A control's details and guidance repeat across hundreds of estates, so each grid
 * row carries an index into a table of the distinct texts rather than the text itself; the Rust side resolves it and
 * compares the words.
 */
class ComplianceReferenceSetTest {

    /** {@code EvidenceVaultService}'s mapper, without the indentation the reference file adds on its own. */
    private static final ObjectMapper BUNDLE = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    @Test
    void theFrameworks() {
        ObjectNode out = RustReference.object();
        ArrayNode frameworks = out.putArray("frameworks");
        for (ComplianceFramework framework : ComplianceFramework.values()) {
            ObjectNode row = frameworks.addObject();
            row.put("name", framework.name());
            row.put("title", framework.getTitle());
            row.put("description", framework.getDescription());
            row.set("controls", BUNDLE.valueToTree(framework.getControls()));
        }
        String[] identifiers = {
            "NIS_2", "nis_2", "NIS2", "nis-2", "N-I-S-2", " nis2 ", "\tdora\n", "\u0000dora", "DORA", "Dora",
            "pci_dss", "PCI-DSS", "pcidss", "pcı_dss", "ISO_27001", "iso-27001", "iso27001", "ISO 27001",
            "eu_cra", "EU-CRA", "eucra", "soc_2", "SOC2", "soc-2", "SOC__2", "--soc2--", "ſoc2", "NIS_2_",
            "nis2 ", "ＤＯＲＡ", "hipaa", "", "   ", "nis", "nis_22", "ISO_27001;", "_",
        };
        ArrayNode rows = out.putArray("identifiers");
        for (String input : identifiers) {
            ObjectNode row = rows.addObject();
            row.put("input", input);
            try {
                row.put("framework", ComplianceFramework.fromIdentifier(input).name());
                row.putNull("refused");
            } catch (InvalidInputException refused) {
                row.putNull("framework");
                row.put("refused", refused.getMessage());
            }
        }
        RustReference.expect("compliance/frameworks.json", out, ComplianceReferenceSetTest.class);
    }

    /** Targets: total, scanned, fresh, window, gate passing, with an inventory. */
    private static final int[][] SHAPES = {
        {0, 0, 0, 30, 0, 0},
        {10, 0, 0, 30, 0, 0},
        {10, 10, 10, 30, 10, 10},
        {10, 10, 0, 30, 10, 10},
        {10, 1, 1, 30, 1, 1},
        {10, 8, 8, 30, 5, 5},
        {10, 10, 9, 14, 9, 9},
        {3, 3, 2, 7, 2, 2},
        {1, 1, 1, 30, 1, 1},
        {1, 1, 0, 30, 0, 0},
        {1, 0, 0, 30, 0, 0},
        {7, 5, 5, 30, 6, 3},
        {200, 199, 199, 30, 199, 179},
        {8, 8, 8, 30, 7, 7},
        {40, 40, 40, 30, 24, 24},
        {40, 40, 40, 30, 23, 23},
        {3, 5, 5, 30, 4, 4},
        {0, 2, 2, 30, 0, 0},
        {10, 10, 12, 30, 10, 10},
        {6, 6, 6, 1, 0, 6},
        // The thresholds' own points: a control at 89 and 59, a framework at 94 with every control compliant, and at
        // 69 with every control partial — the one place the 70 decides alone.
        {100, 100, 100, 30, 89, 59},
        {100, 100, 100, 30, 90, 96},
        {100, 100, 97, 30, 100, 100},
    };

    /** Open issues: critical, high, medium, low, KEV, overdue, secrets, code, IaC. */
    private static final long[][] FINDINGS = {
        {0, 0, 0, 0, 0, 0, 0, 0, 0},
        {1, 0, 0, 0, 0, 0, 0, 0, 0},
        {2, 0, 0, 0, 0, 0, 0, 0, 0},
        {3, 10, 15, 20, 2, 4, 2, 5, 3},
        {0, 5, 0, 0, 0, 0, 0, 0, 0},
        {0, 6, 0, 0, 0, 0, 0, 0, 0},
        {2, 6, 0, 0, 1, 0, 0, 0, 0},
        {0, 0, 0, 0, 1, 0, 0, 0, 0},
        {0, 0, 0, 0, 3, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 3, 0, 0, 0},
        {0, 0, 0, 0, 0, 4, 0, 0, 0},
        {0, 0, 0, 0, 0, 5, 0, 0, 0},
        {5, 0, 0, 0, 3, 5, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 1, 0, 0},
        {0, 0, 0, 0, 0, 0, 4, 0, 0},
        {0, 0, 0, 0, 0, 0, 5, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 1, 0},
        {0, 0, 0, 0, 0, 0, 0, 2, 0},
        {0, 0, 0, 0, 0, 0, 0, 3, 0},
        {0, 0, 0, 0, 0, 0, 0, 8, 0},
        {0, 0, 0, 0, 0, 0, 0, 9, 0},
        {0, 0, 0, 0, 0, 0, 0, 16, 0},
        {0, 0, 0, 0, 0, 0, 0, 100, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 1},
        {0, 0, 0, 0, 0, 0, 0, 0, 4},
        {0, 0, 0, 0, 0, 0, 0, 0, 5},
        {0, 0, 0, 0, 0, 0, 0, 0, 7},
        {0, 0, 0, 0, 0, 0, 0, 0, 50},
        // Past an `int`: the engine casts each count before it multiplies, and Java's int wraps.
        {3_000_000_000L, 0, 0, 0, 2_147_483_648L, 0, 4_294_967_297L, 2_147_483_647L, 4_294_967_296L},
        {0, 0, 0, 0, 0, 107_374_183L, 107_374_183L, 429_496_730L, 214_748_365L},
        {3, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 4, 0, 8, 4},
    };

    /** encryption, external KMS, mirror, four eyes, provider, password open, password accounts, without a factor. */
    private static final long[][] PLATFORMS = {
        {1, 1, 1, 1, 1, 0, 0, 0},
        {0, 0, 1, 1, 1, 0, 0, 0},
        {1, 1, 0, 1, 1, 0, 0, 0},
        {1, 1, 1, 0, 1, 0, 0, 0},
        {1, 1, 1, 1, 1, 1, 0, 0},
        {1, 1, 1, 1, 0, 1, 3, 3},
        {1, 1, 1, 1, 0, 1, 3, 0},
        {1, 1, 1, 1, 0, 1, 3, 1},
        {1, 1, 1, 1, 0, 1, 0, 0},
        {1, 1, 0, 1, 0, 1, 2, 0},
        {0, 0, 0, 0, 0, 1, 5, 5},
        {0, 0, 0, 0, 1, 1, 0, 0},
        {1, 0, 1, 1, 0, 0, 1, 0},
    };

    @Test
    void theEngine() {
        ObjectNode out = RustReference.object();
        Texts texts = new Texts();
        ArrayNode rows = out.putArray("rows");
        for (int[] shape : SHAPES) {
            engineRow(rows, texts, input(shape, FINDINGS[0], true), PLATFORMS[0]);
            engineRow(rows, texts, input(shape, FINDINGS[3], true), PLATFORMS[0]);
        }
        for (long[] findings : FINDINGS) {
            engineRow(rows, texts, input(SHAPES[2], findings, true), PLATFORMS[0]);
            engineRow(rows, texts, input(SHAPES[4], findings, true), PLATFORMS[0]);
            engineRow(rows, texts, input(SHAPES[6], findings, false), PLATFORMS[0]);
        }
        engineRow(rows, texts, input(SHAPES[20], FINDINGS[0], true), PLATFORMS[0]);
        engineRow(rows, texts, input(SHAPES[21], FINDINGS[5], true), PLATFORMS[0]);
        engineRow(rows, texts, input(SHAPES[22], FINDINGS[31], true), PLATFORMS[0]);
        for (long[] platform : PLATFORMS) {
            engineRow(rows, texts, input(SHAPES[0], FINDINGS[0], true), platform);
            engineRow(rows, texts, input(SHAPES[2], FINDINGS[0], true), platform);
            engineRow(rows, texts, input(SHAPES[2], FINDINGS[0], false), platform);
            engineRow(rows, texts, input(SHAPES[3], FINDINGS[13], true), platform);
            engineRow(rows, texts, input(SHAPES[5], FINDINGS[3], true), platform);
        }
        out.set("texts", texts.node());
        // Two evaluations whole, as the bundle's section 01 carries them: one measured, one resting on nothing.
        ArrayNode shapes = out.putArray("shapes");
        for (PostureInput input : List.of(input(SHAPES[5], FINDINGS[3], true), input(SHAPES[0], FINDINGS[0], true))) {
            ObjectNode row = shapes.addObject();
            row.set("input", inputNode(input));
            row.set("evaluation", BUNDLE.valueToTree(ComplianceEngine.evaluate(ComplianceFramework.SOC_2, input,
                    platform(PLATFORMS[7]))));
        }
        RustReference.expect("compliance/engine.json", out, ComplianceReferenceSetTest.class);
    }

    private static PostureInput input(int[] shape, long[] f, boolean auditValid) {
        return new PostureInput(shape[0], shape[1], shape[2], shape[3], shape[4],
                f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], shape[5], auditValid);
    }

    private static PlatformPosture platform(long[] p) {
        return new PlatformPosture(p[0] == 1, p[1] == 1, p[2] == 1, p[3] == 1, p[4] == 1, p[5] == 1,
                new PasswordAccounts(p[6], p[7]));
    }

    private static ArrayNode inputNode(PostureInput input) {
        ArrayNode node = RustReference.object().arrayNode();
        node.add(input.totalTargets()).add(input.scannedTargets()).add(input.freshlyScannedTargets())
                .add(input.freshnessWindowDays()).add(input.gatePassingTargets()).add(input.criticalIssues())
                .add(input.highIssues()).add(input.mediumIssues()).add(input.lowIssues()).add(input.kevIssues())
                .add(input.overdueIssues()).add(input.secretIssues()).add(input.sastIssues()).add(input.iacIssues())
                .add(input.targetsWithSbom()).add(input.auditChainValid());
        return node;
    }

    private static void engineRow(ArrayNode rows, Texts texts, PostureInput input, long[] platform) {
        ObjectNode row = rows.addObject();
        row.set("input", inputNode(input));
        ArrayNode platformNode = row.putArray("platform");
        for (long value : platform) {
            platformNode.add(value);
        }
        ArrayNode frameworks = row.putArray("frameworks");
        ObjectNode categories = row.putObject("categories");
        for (ComplianceEvaluation evaluation : ComplianceEngine.evaluateAll(input, platform(platform))) {
            frameworks.add(evaluation.framework().name() + " " + evaluation.scorePercentage() + " "
                    + evaluation.overallStatus().name());
            for (ComplianceEvaluation.ControlAssessment control : evaluation.controls()) {
                // The same category is assessed the same way in every framework that maps it: one entry, checked
                // against every control of that category on the Rust side.
                String line = control.status().name() + " " + control.scorePercentage() + " "
                        + texts.of(control.details()) + " " + texts.of(control.remediationGuidance());
                JsonNode previous = categories.get(control.control().category().name());
                if (previous != null && !previous.asText().equals(line)) {
                    throw new AssertionError("one category assessed two ways: " + previous + " / " + line);
                }
                categories.put(control.control().category().name(), line);
            }
        }
    }

    /** Each distinct text once, by its first appearance. */
    private static final class Texts {
        private final Map<String, Integer> indexes = new LinkedHashMap<>();

        int of(String text) {
            return indexes.computeIfAbsent(text, ignored -> indexes.size());
        }

        ArrayNode node() {
            ArrayNode node = RustReference.object().arrayNode();
            indexes.keySet().forEach(node::add);
            return node;
        }
    }

    private static final Instant NOW = Instant.parse("2026-11-17T10:00:00Z");

    @Test
    void theStatementOfApplicability() {
        ObjectNode out = RustReference.object();
        out.put("now", NOW.toString());
        // Every declaration a line can carry, against every verdict the control can have — or none.
        ArrayNode divergences = out.putArray("divergences");
        ComplianceControl first = ComplianceFramework.ISO_27001.getControls().getFirst();
        List<ComplianceControl.Status> statuses = new ArrayList<>(Arrays.asList(ComplianceControl.Status.values()));
        statuses.add(null);
        List<Implementation> implementations = new ArrayList<>(Arrays.asList(Implementation.values()));
        implementations.add(null);
        for (Applicability applicability : Applicability.values()) {
            for (String justification : Arrays.asList(null, "", " \t", "why")) {
                for (Implementation implementation : implementations) {
                    for (EvidenceSource source : EvidenceSource.values()) {
                        for (ComplianceControl.Status measured : statuses) {
                            Declaration declaration = new Declaration("ISO_27001", first.id(), applicability,
                                    justification, implementation, source, null, null, null, null, null, null);
                            List<ComplianceEvaluation.ControlAssessment> controls = measured == null
                                    ? List.of()
                                    : List.of(new ComplianceEvaluation.ControlAssessment(first, measured, 0, "", ""));
                            StatementOfApplicability.SoaStatement statement = StatementOfApplicability.reconcile(
                                    new ComplianceEvaluation(ComplianceFramework.ISO_27001, 0,
                                            ComplianceControl.Status.NO_DATA, controls),
                                    List.of(declaration), NOW);
                            divergences.add(applicability + "|" + justification + "|" + implementation + "|" + source
                                    + "|" + measured + "|" + statement.lines().getFirst().divergence());
                        }
                    }
                }
            }
        }
        ArrayNode statements = out.putArray("statements");
        for (Scenario scenario : soaScenarios()) {
            ObjectNode row = statements.addObject();
            row.put("framework", scenario.evaluation().framework().name());
            ArrayNode measured = row.putArray("measured");
            scenario.evaluation().controls().forEach(control ->
                    measured.add(control.control().id() + " " + control.status().name()));
            row.set("declarations", BUNDLE.valueToTree(scenario.declarations()));
            row.set("statement", BUNDLE.valueToTree(
                    StatementOfApplicability.reconcile(scenario.evaluation(), scenario.declarations(), NOW)));
        }
        RustReference.expect("compliance/soa.json", out, ComplianceReferenceSetTest.class);
    }

    private record Scenario(ComplianceEvaluation evaluation, List<Declaration> declarations) {}

    private static Declaration declared(String framework, String control, Implementation implementation,
            EvidenceSource source, Instant reviewDue) {
        return new Declaration(framework, control, Applicability.APPLICABLE, "in scope", implementation, source,
                source == EvidenceSource.VECTISPIRE ? null : "ISMS/A.8.8 register", "ciso", "auditor",
                Instant.parse("2026-01-02T03:04:05.123Z"), Instant.parse("2026-06-01T00:00:00Z"), reviewDue);
    }

    private static List<Scenario> soaScenarios() {
        PlatformPosture all = PlatformPosture.FULLY_ENABLED;
        ComplianceEvaluation iso = ComplianceEngine.evaluate(ComplianceFramework.ISO_27001,
                input(SHAPES[5], FINDINGS[3], true), all);
        ComplianceEvaluation isoClean = ComplianceEngine.evaluate(ComplianceFramework.ISO_27001,
                input(SHAPES[2], FINDINGS[0], true), all);
        ComplianceEvaluation isoEmpty = ComplianceEngine.evaluate(ComplianceFramework.ISO_27001,
                input(SHAPES[0], FINDINGS[0], true), all);
        ComplianceEvaluation dora = ComplianceEngine.evaluate(ComplianceFramework.DORA,
                input(SHAPES[3], FINDINGS[13], true), platform(PLATFORMS[2]));
        Instant before = NOW.minusNanos(1);
        Instant after = NOW.plusSeconds(86_400);
        List<Declaration> mixed = List.of(
                declared("ISO_27001", "ISO-A.8.8", Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE, before),
                declared("ISO_27001", "ISO-A.8.28", Implementation.PLANNED, EvidenceSource.BOTH, NOW),
                declared("ISO_27001", "ISO-A.8.28", Implementation.IMPLEMENTED, EvidenceSource.BOTH, after),
                new Declaration("ISO_27001", "ISO-A.8.9", Applicability.EXCLUDED, "  ", null, EvidenceSource.EXTERNAL,
                        null, null, null, null, null, before),
                declared("ISO_27001", "ISO-A.9.9", Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE, before),
                declared("NIS_2", "ISO-A.5.15", Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE, before),
                declared("OWASP_TOP_10", "A01", Implementation.PLANNED, EvidenceSource.EXTERNAL, null));
        List<Declaration> complete = List.of(
                declared("ISO_27001", "ISO-A.8.8", Implementation.PLANNED, EvidenceSource.VECTISPIRE, null),
                declared("ISO_27001", "ISO-A.8.28", Implementation.NOT_IMPLEMENTED, EvidenceSource.VECTISPIRE, after),
                declared("ISO_27001", "ISO-A.8.9", Implementation.PARTIALLY_IMPLEMENTED, EvidenceSource.BOTH, null),
                new Declaration("ISO_27001", "ISO-A.5.15", Applicability.EXCLUDED, "no code is written here",
                        Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE, null, "cto", null, null, null, before));
        List<Declaration> doraLines = List.of(
                declared("DORA", "DORA-ART09-ICT", Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE, null),
                declared("DORA", "DORA-ART11-THIRD", Implementation.PLANNED, EvidenceSource.VECTISPIRE, NOW),
                declared("DORA", "DORA-ART13-SECRETS", Implementation.IMPLEMENTED, EvidenceSource.BOTH, null),
                declared("DORA", "DORA-ART16-INCIDENT", Implementation.IMPLEMENTED, EvidenceSource.EXTERNAL, before));
        return List.of(
                new Scenario(iso, mixed),
                new Scenario(isoClean, complete),
                new Scenario(isoEmpty, complete),
                new Scenario(iso, List.of()),
                new Scenario(dora, doraLines),
                new Scenario(new ComplianceEvaluation(ComplianceFramework.ISO_27001, 0, ComplianceControl.Status.NO_DATA,
                        List.of()), complete));
    }

    @Test
    void theHistory() {
        ObjectNode out = RustReference.object();
        ArrayNode series = out.putArray("series");
        for (List<ComplianceSnapshot> snapshots : historyScenarios()) {
            for (ComplianceFramework framework : List.of(ComplianceFramework.ISO_27001, ComplianceFramework.NIS_2)) {
                ObjectNode row = series.addObject();
                row.put("framework", framework.name());
                row.set("snapshots", BUNDLE.valueToTree(snapshots));
                row.set("series", BUNDLE.valueToTree(ComplianceHistory.of(framework, snapshots)));
            }
        }
        RustReference.expect("compliance/history.json", out, ComplianceReferenceSetTest.class);
    }

    private static ComplianceSnapshot snapshot(String period, ComplianceFramework framework, int score, int targets,
            int freshness, boolean endOfLife, boolean code) {
        return new ComplianceSnapshot(period, framework, score,
                score >= 95 ? ComplianceControl.Status.COMPLIANT : ComplianceControl.Status.PARTIAL, targets,
                targets - 1, targets - 2, freshness, endOfLife, code, 4, 3, 1,
                NOW.minusMillis(500));
    }

    private static List<List<ComplianceSnapshot>> historyScenarios() {
        ComplianceFramework iso = ComplianceFramework.ISO_27001;
        ComplianceFramework nis = ComplianceFramework.NIS_2;
        return List.of(
                List.of(),
                List.of(snapshot("2026-01", iso, 80, 10, 30, true, true)),
                List.of(snapshot("2026-01", iso, 80, 10, 30, true, true), snapshot("2026-02", iso, 60, 13, 30, true, true),
                        snapshot("2026-03", iso, 90, 9, 30, true, true)),
                List.of(snapshot("2026-03", iso, 84, 10, 30, true, true), snapshot("2026-01", iso, 80, 10, 30, true, true),
                        snapshot("2026-02", iso, 82, 10, 30, true, true), snapshot("2026-04", iso, 83, 10, 30, true, true),
                        snapshot("2026-05", iso, 82, 10, 30, true, true), snapshot("2026-06", iso, 80, 10, 30, true, true),
                        snapshot("2026-02", nis, 10, 99, 7, false, false)),
                List.of(snapshot("2026-01", iso, 80, 10, 30, true, true), snapshot("2026-02", iso, 70, 10, 14, true, true),
                        snapshot("2026-03", iso, 72, 10, 14, false, true), snapshot("2026-04", iso, 75, 10, 14, true, true),
                        snapshot("2026-05", iso, 75, 10, 14, true, false), snapshot("2026-06", iso, 99, 10, 14, true, true),
                        snapshot("2026-07", iso, 99, 10, 14, false, false), snapshot("2026-07", iso, 50, 10, 14, false, false)),
                List.of(snapshot("2026-01", nis, 100, 5, 30, true, true), snapshot("2025-12", nis, 0, 5, 30, true, true),
                        snapshot("2026-01", iso, 1, 5, 30, true, true), snapshot("2026-02", nis, -5, 5, 30, true, true),
                        snapshot("2026-03", nis, Integer.MAX_VALUE, 5, 30, true, true),
                        snapshot("2026-04", nis, Integer.MIN_VALUE, 5, 30, true, true)),
                List.of(snapshot("2026-1", iso, 50, 3, 30, true, true), snapshot("2026-10", iso, 55, 3, 30, true, true),
                        snapshot("2026-02", iso, 56, 3, 30, true, true)));
    }

    @Test
    void theRecords() {
        ObjectNode out = RustReference.object();
        ArrayNode scopes = out.putArray("scope");
        int[][] coverages = {{0, 0, 0, 0, 0}, {40, 31, 20, 6, 5}, {10, 12, 12, 0, 0}, {-3, 4, 1, 1, 2}, {5, 5, 5, 0, 0},
            {1, 0, 0, 0, 0}, {0, -2, 0, 0, 0}, {Integer.MAX_VALUE, Integer.MIN_VALUE, 0, 0, 0}};
        for (int[] c : coverages) {
            ScopeCoverage coverage = new ScopeCoverage(c[0], c[1], c[2], c[3], c[4]);
            ObjectNode row = scopes.addObject();
            row.set("coverage", BUNDLE.valueToTree(coverage));
            row.put("unaccountedFor", coverage.unaccountedFor());
            row.put("declared", coverage.declared());
        }
        ArrayNode manifests = out.putArray("manifests");
        manifests.add(BUNDLE.valueToTree(new EvidenceBundleManifest("1.5", Instant.parse("2026-08-22T10:00:00Z"),
                "ciso@corp.internal", "VERIFIED_INTACT", 150L,
                List.of(new EvidenceBundleManifest.EvidenceFileEntry("01_compliance_summary.json", "Compliance summary",
                                1024, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                        new EvidenceBundleManifest.EvidenceFileEntry("02_audit_log.jsonl", "Audit trail", 0, "00")),
                List.of())));
        manifests.add(BUNDLE.valueToTree(new EvidenceBundleManifest("1.5", Instant.parse("2026-08-22T10:00:00.000123Z"),
                "auditor", "CHAIN_INTEGRITY_COMPROMISED", null, List.of(),
                List.of(new EvidenceBundleManifest.WithheldSection("02_audit_log.jsonl",
                        "describes the whole estate")))));
        RustReference.expect("compliance/records.json", out, ComplianceReferenceSetTest.class);
    }

    /** One kind of evidence, as its constructor is handed it — the Rust side builds it from the same values. */
    private record Spec(String target, Observation observation, List<String> examined, List<String> analysed,
            List<String> reaches) {

        Evidence evidence() {
            return new Evidence(ComplianceReferenceSetTest.target(target), observation,
                    Optional.ofNullable(examined).map(types -> types.stream()
                            .map(type -> FindingType.fromWireName(type).orElseThrow())
                            .collect(java.util.stream.Collectors.toSet())),
                    Optional.ofNullable(analysed).map(languages -> languages.stream()
                            .map(language -> Language.fromWireName(language).orElseThrow())
                            .collect(java.util.stream.Collectors.toSet())),
                    Optional.ofNullable(reaches).map(Set::copyOf));
        }

        ObjectNode node() {
            ObjectNode node = RustReference.object();
            node.put("target", target);
            node.put("observation", observation.name());
            node.set("examined", list(examined));
            node.set("analysed", list(analysed));
            node.set("codeReaches", list(reaches));
            return node;
        }
    }

    private static ScanTarget target(String key) {
        String[] parts = key.split(":");
        long id = Long.parseLong(parts[1]);
        return parts[0].equals("repo") ? new ScanTarget.Repository(id) : new ScanTarget.Container(id);
    }

    private static JsonNode list(List<String> values) {
        if (values == null) {
            return RustReference.object().nullNode();
        }
        ArrayNode node = RustReference.object().arrayNode();
        values.forEach(node::add);
        return node;
    }

    private static final List<String> EVERY = List.of("vulnerability", "eol", "license", "secret", "iac", "sast", "quality");

    private static List<String> everyBut(String type) {
        return EVERY.stream().filter(each -> !each.equals(type)).toList();
    }

    private static final List<Spec> KINDS = List.of(
            new Spec("repo:1", Observation.OK, EVERY, List.of("java"), List.of("A03")),
            new Spec("repo:2", Observation.OK, EVERY, List.of("java"), List.of("A02")),
            new Spec("repo:3", Observation.OK, everyBut("secret"), List.of("java"), List.of("A03")),
            new Spec("repo:4", Observation.LAST_SCAN_FAILED, null, null, null),
            new Spec("repo:5", Observation.NEVER_SCANNED, null, null, null),
            new Spec("repo:6", Observation.OK, null, null, null),
            new Spec("container:7", Observation.OK, List.of("vulnerability", "eol", "license"), null, null),
            new Spec("container:8", Observation.NEVER_SCANNED, null, null, null),
            new Spec("repo:9", Observation.OK, everyBut("eol"), List.of("java"), List.of()),
            new Spec("repo:10", Observation.OK, everyBut("sast"), List.of("java"), List.of("A03")),
            new Spec("repo:11", Observation.OK, EVERY, null, List.of("A03")),
            new Spec("container:12", Observation.LAST_SCAN_FAILED, List.of("vulnerability"), null, null),
            new Spec("repo:13", Observation.IN_PROGRESS, EVERY, List.of("java"), List.of("A03")),
            new Spec("container:14", Observation.OK, List.of("vulnerability"), null, null),
            new Spec("repo:15", Observation.OK, EVERY, List.of(), List.of("A03", "A02")));

    @Test
    void theOwaspGrid() {
        ObjectNode out = RustReference.object();
        ArrayNode categories = out.putArray("categories");
        OwaspCoverage.CATEGORIES.forEach((id, title) -> categories.addArray().add(id).add(title));
        ArrayNode kinds = out.putArray("kinds");
        KINDS.forEach(kind -> kinds.add(kind.node()));
        Reasons reasons = new Reasons();
        ArrayNode measurements = out.putArray("measurements");

        List<List<Integer>> scopes = new ArrayList<>();
        for (int a = 0; a < KINDS.size(); a++) {
            scopes.add(List.of(a));
        }
        for (int a = 0; a < 8; a++) {
            for (int b = a + 1; b < 8; b++) {
                scopes.add(List.of(a, b));
            }
        }
        for (List<Integer> scope : scopes) {
            for (int variant = 0; variant < 3; variant++) {
                for (boolean code : List.of(true, false)) {
                    for (boolean endOfLife : List.of(true, false)) {
                        measurements.add(folded(scope, variant, code, endOfLife, reasons));
                    }
                }
            }
        }
        for (int a = 0; a < 8; a++) {
            for (int b = a + 1; b < 8; b++) {
                for (int c = b + 1; c < 8; c++) {
                    measurements.add(folded(List.of(a, b, c), 1, true, true, reasons));
                }
            }
        }
        for (ObjectNode chosen : chosenMeasurements()) {
            measurements.add(measured(chosen, reasons));
        }
        ArrayNode refusals = out.putArray("assessTargetRefusals");
        for (List<Integer> scope : List.of(List.<Integer>of(), List.of(0, 1))) {
            try {
                OwaspCoverage.assessTarget(new Measurement(true, true, Map.of(), Set.of(), Map.of(),
                        scope.stream().map(index -> KINDS.get(index).evidence()).toList()));
                refusals.addNull();
            } catch (IllegalArgumentException refused) {
                refusals.add(refused.getMessage());
            }
        }
        out.set("acrossTargets", acrossTargets());
        out.set("sentences", sentences());
        out.set("placement", placement());
        out.set("reasons", reasons.node());
        RustReference.expect("compliance/owasp.json", out, ComplianceReferenceSetTest.class);
    }

    /** The fold test's construction: each target its variant's backlog, the first repository one secret settled. */
    private static ObjectNode folded(List<Integer> scope, int variant, boolean code, boolean endOfLife, Reasons reasons) {
        List<Map<FindingType, Long>> backlogs = List.of(
                Map.of(),
                Map.of(FindingType.SECRET, 1L),
                Map.of(FindingType.VULNERABILITY, 2L, FindingType.EOL, 1L));
        Map<FindingType, Long> unsettled = new EnumMap<>(FindingType.class);
        Map<FindingType, Long> all = new EnumMap<>(FindingType.class);
        Map<String, Long> byCategory = new TreeMap<>();
        boolean firstRepository = true;
        for (int index : scope) {
            Evidence evidence = KINDS.get(index).evidence();
            boolean repository = evidence.target() instanceof ScanTarget.Repository;
            backlogs.get(variant).forEach((type, count) -> {
                if (repository || OwaspCoverage.examinable(type, evidence.target())) {
                    unsettled.merge(type, count, Long::sum);
                    all.merge(type, count, Long::sum);
                }
            });
            if (repository && firstRepository) {
                all.merge(FindingType.SECRET, 1L, Long::sum);
                firstRepository = false;
            }
            if (repository && variant == 1) {
                byCategory.merge("A03", 1L, Long::sum);
            }
        }
        ObjectNode spec = RustReference.object();
        ArrayNode targets = spec.putArray("targets");
        scope.forEach(targets::add);
        spec.put("endOfLife", endOfLife);
        spec.put("code", code);
        spec.set("open", byType(unsettled));
        spec.set("openAll", byType(all));
        spec.set("declared", list(List.of("A02", "A03")));
        spec.set("byCategory", BUNDLE.valueToTree(byCategory));
        spec.set("byCategoryAll", BUNDLE.valueToTree(byCategory));
        return measured(spec, reasons);
    }

    private static ObjectNode byType(Map<FindingType, Long> counts) {
        ObjectNode node = RustReference.object();
        counts.forEach((type, count) -> node.put(type.wireName(), count));
        return node;
    }

    /** The cases the fold does not reach: no target, nothing declared, a switch off with a backlog, sums that wrap. */
    private static List<ObjectNode> chosenMeasurements() {
        List<ObjectNode> chosen = new ArrayList<>();
        chosen.add(chosen(List.of(), true, true, Map.of(), List.of(), Map.of()));
        chosen.add(chosen(List.of(), true, false, Map.of(), List.of("A03"), Map.of()));
        chosen.add(chosen(List.of(), false, true, Map.of("eol", 5L, "vulnerability", 0L), List.of("A03"), Map.of()));
        chosen.add(chosen(List.of(0), true, true, Map.of("sast", 4L, "plugin", 2L, "quality", 1L), List.of(),
                Map.of("A03", 3L)));
        chosen.add(chosen(List.of(0), false, true, Map.of("eol", 3L), List.of("A06", "A11", "A01"),
                Map.of("A06", 2L, "A01", 1L, "A11", 4L)));
        chosen.add(chosen(List.of(0), false, false, Map.of("eol", 3L), List.of("A06", "A05"), Map.of("A06", 2L)));
        chosen.add(chosen(List.of(0, 6), true, true, Map.of("vulnerability", Long.MAX_VALUE, "eol", 1L), List.of(),
                Map.of()));
        chosen.add(chosen(List.of(0), true, true, Map.of("secret", -1L), List.of(), Map.of()));
        chosen.add(chosen(List.of(9), true, true, Map.of(), List.of("A03"), Map.of("A03", 0L)));
        chosen.add(chosen(List.of(9, 10, 14), true, true, Map.of(), List.of("A03", "A07", "A10"), Map.of()));
        chosen.add(chosen(List.of(11, 13, 14, 6), true, true, Map.of(), List.of("A06"), Map.of()));
        chosen.add(chosen(List.of(3, 4, 5, 2, 8, 9, 10, 12), true, true, Map.of(), List.of("A03", "A02"), Map.of()));
        chosen.add(chosen(List.of(1, 14), true, true, Map.of("iac", 2L), List.of("A05", "A02"), Map.of("A02", 7L)));
        // Fewer findings with the settled ones than without: two reads, and the settled count never goes below zero.
        ObjectNode fewer = chosen(List.of(0), true, true, Map.of("secret", 3L), List.of("A03"), Map.of("A03", 2L));
        fewer.set("openAll", BUNDLE.valueToTree(new TreeMap<>(Map.of("secret", 1L))));
        fewer.set("byCategoryAll", BUNDLE.valueToTree(new TreeMap<>(Map.of())));
        chosen.add(fewer);
        return chosen;
    }

    private static ObjectNode chosen(List<Integer> targets, boolean endOfLife, boolean code, Map<String, Long> open,
            List<String> declared, Map<String, Long> byCategory) {
        ObjectNode spec = RustReference.object();
        ArrayNode targetNode = spec.putArray("targets");
        targets.forEach(targetNode::add);
        spec.put("endOfLife", endOfLife);
        spec.put("code", code);
        spec.set("open", BUNDLE.valueToTree(new TreeMap<>(open)));
        spec.set("openAll", BUNDLE.valueToTree(new TreeMap<>(open)));
        spec.set("declared", list(declared));
        spec.set("byCategory", BUNDLE.valueToTree(new TreeMap<>(byCategory)));
        spec.set("byCategoryAll", BUNDLE.valueToTree(new TreeMap<>(byCategory)));
        return spec;
    }

    /** Builds the measurement the spec describes, and writes beside it the grid, the split and a target's own grid. */
    private static ObjectNode measured(ObjectNode spec, Reasons reasons) {
        List<Evidence> targets = new ArrayList<>();
        spec.get("targets").forEach(index -> targets.add(KINDS.get(index.asInt()).evidence()));
        Set<String> declared = new LinkedHashSet<>();
        spec.get("declared").forEach(category -> declared.add(category.asText()));
        Measurement unsettled = new Measurement(spec.get("endOfLife").asBoolean(), spec.get("code").asBoolean(),
                types(spec.get("open")), declared, categories(spec.get("byCategory")), targets);
        Measurement all = new Measurement(spec.get("endOfLife").asBoolean(), spec.get("code").asBoolean(),
                types(spec.get("openAll")), declared, categories(spec.get("byCategoryAll")), targets);
        Grid grid = OwaspCoverage.assess(unsettled);
        spec.set("grid", lines(grid, OwaspCoverage.split(grid, OwaspCoverage.assess(all)), reasons));
        if (targets.size() == 1) {
            Grid own = OwaspCoverage.assessTarget(unsettled);
            spec.set("target", lines(own, OwaspCoverage.split(own, OwaspCoverage.assessTarget(all)), reasons));
        }
        return spec;
    }

    private static Map<FindingType, Long> types(JsonNode node) {
        Map<FindingType, Long> counts = new EnumMap<>(FindingType.class);
        node.properties().forEach(entry ->
                counts.put(FindingType.fromWireName(entry.getKey()).orElseThrow(), entry.getValue().asLong()));
        return counts;
    }

    private static Map<String, Long> categories(JsonNode node) {
        Map<String, Long> counts = new TreeMap<>();
        node.properties().forEach(entry -> counts.put(entry.getKey(), entry.getValue().asLong()));
        return counts;
    }

    /** One line per category: id, state, open (the grid's findings), settled, and the reason's index. */
    private static ObjectNode lines(Grid grid, List<Split> splits, Reasons reasons) {
        ObjectNode node = RustReference.object();
        node.put("covered", grid.covered());
        node.put("withFindings", grid.withFindings());
        node.put("unmeasured", grid.unmeasured());
        ArrayNode lines = node.putArray("lines");
        for (int index = 0; index < grid.lines().size(); index++) {
            CoverageLine line = grid.lines().get(index);
            Split split = splits.get(index);
            if (!split.id().equals(line.id()) || split.state() != line.state() || split.open() != line.findings()) {
                throw new AssertionError("a split that is not its grid's: " + split + " / " + line);
            }
            if (!line.because().equals(line.reason().sentence())) {
                throw new AssertionError("a line whose sentence is not its reason's: " + line);
            }
            lines.add(line.id() + " " + line.state() + " " + line.findings() + " " + split.settled() + " "
                    + reasons.of(line.reason()));
        }
        return node;
    }

    /** Each distinct reason once, with its sentence. */
    private static final class Reasons {
        private final Map<String, Integer> indexes = new LinkedHashMap<>();
        private final ArrayNode node = RustReference.object().arrayNode();

        int of(CoverageReason reason) {
            ObjectNode written = BUNDLE.valueToTree(reason);
            written.put("sentence", reason.sentence());
            return indexes.computeIfAbsent(written.toString(), ignored -> {
                node.add(written);
                return indexes.size();
            });
        }

        ArrayNode node() {
            return node;
        }
    }

    private static ArrayNode acrossTargets() {
        Object[][][] cases = {
            {{"A07"}},
            {{"A07"}, {"NOT_MEASURED", 2L, 1L}},
            {{"A07"}, {"NOT_COVERED", 0L, 0L}},
            {{"A03"}, {"NOT_COVERED", 0L, 0L}},
            {{"A03"}, {"NO_FINDING", 0L, 3L}, {"NOT_COVERED", 0L, 1L}},
            {{"A05"}, {"NO_FINDING", 0L, 0L}, {"NOT_MEASURED", 0L, 2L}},
            {{"A05"}, {"FINDINGS", 0L, 0L}, {"NO_FINDING", 0L, 0L}},
            {{"A05"}, {"FINDINGS", 0L, 0L}, {"NOT_COVERED", 0L, 5L}},
            {{"A06"}, {"FINDINGS", 3L, 0L}, {"NOT_MEASURED", 0L, 2L}},
            {{"A01"}, {"NOT_COVERED", 0L, 0L}, {"NOT_COVERED", 0L, 0L}},
            {{"A06"}, {"FINDINGS", Long.MAX_VALUE, 0L}, {"FINDINGS", 1L, 0L}},
            {{"A06"}, {"NO_FINDING", -1L, 0L}, {"NO_FINDING", 0L, 0L}},
            {{"A11"}, {"NOT_COVERED", 0L, 0L}},
            {{"A11"}, {"NOT_MEASURED", 0L, 0L}},
            {{"A02"}, {"NOT_MEASURED", 0L, 0L}, {"NOT_MEASURED", 0L, 0L}, {"NOT_COVERED", 0L, 0L}},
        };
        ArrayNode rows = RustReference.object().arrayNode();
        for (Object[][] c : cases) {
            String id = (String) c[0][0];
            List<Split> lines = new ArrayList<>();
            for (int index = 1; index < c.length; index++) {
                lines.add(new Split(id, State.valueOf((String) c[index][0]), (Long) c[index][1], (Long) c[index][2]));
            }
            ObjectNode row = rows.addObject();
            row.put("id", id);
            row.set("lines", BUNDLE.valueToTree(lines));
            row.set("fold", BUNDLE.valueToTree(OwaspCoverage.acrossTargets(id, lines).orElse(null)));
        }
        return rows;
    }

    /** Every code's sentence, the two no grid reaches today among them, singular and plural. */
    private static ArrayNode sentences() {
        Map<Gap, Long> everyGap = new EnumMap<>(Gap.class);
        long count = 1;
        for (Gap gap : Gap.values()) {
            everyGap.put(gap, count++);
        }
        List<GapCount> gaps = everyGap.entrySet().stream().map(gap -> new GapCount(gap.getKey(), gap.getValue())).toList();
        ArrayNode rows = RustReference.object().arrayNode();
        for (ReasonCode code : ReasonCode.values()) {
            for (CoverageReason reason : List.of(
                    new CoverageReason(code, List.of("eol", "vulnerability"), 21L, 30L, gaps),
                    new CoverageReason(code, List.of("secret"), 1L, 1L, List.of(new GapCount(Gap.STEP_ABSENT, 1L))),
                    new CoverageReason(code, List.of(), 2L, 1L, List.of()))) {
                ObjectNode row = BUNDLE.valueToTree(reason);
                row.put("sentence", reason.sentence());
                rows.add(row);
            }
        }
        return rows;
    }

    private static ObjectNode placement() {
        ObjectNode out = RustReference.object();
        ArrayNode placements = out.putArray("placementOf");
        ArrayNode examinable = out.putArray("examinable");
        for (FindingType type : FindingType.values()) {
            for (String declared : Arrays.asList(null, "A03", "A06", "a03", "A11", "", " A03")) {
                placements.add(type.wireName() + "|" + declared + "|"
                        + OwaspCoverage.placementOf(type, declared).orElse(null));
            }
            examinable.add(type.wireName() + "|" + OwaspCoverage.examinable(type, new ScanTarget.Repository(1)) + "|"
                    + OwaspCoverage.examinable(type, new ScanTarget.Container(1)));
        }
        ArrayNode placedIn = out.putArray("typesPlacedIn");
        for (String category : List.of("A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10", "A11")) {
            placedIn.add(category + "|" + String.join(",", OwaspCoverage.typesPlacedIn(category).stream()
                    .map(FindingType::wireName).sorted().toList()));
        }
        out.put("typesPlacedAnywhere", String.join(",", OwaspCoverage.typesPlacedAnywhere().stream()
                .map(FindingType::wireName).sorted().toList()));
        ArrayNode unplaced = out.putArray("unplacedCode");
        Object[][] cases = {
            {10L, Map.of("A03", 3L, "A11", 4L, "a03", 2L)},
            {2L, Map.of("A03", 5L)},
            {0L, Map.of()},
            {7L, Map.of("A01", 1L, "A02", 1L, "A10", 1L)},
            {Long.MAX_VALUE, Map.of("A01", -1L)},
            {-4L, Map.of()},
        };
        for (Object[] c : cases) {
            @SuppressWarnings("unchecked")
            Map<String, Long> byCategory = (Map<String, Long>) c[1];
            ObjectNode row = unplaced.addObject();
            row.put("openCode", (Long) c[0]);
            row.set("byCategory", BUNDLE.valueToTree(new TreeMap<>(byCategory)));
            row.put("unplaced", OwaspCoverage.unplacedCode((Long) c[0], byCategory));
        }
        ArrayNode evidence = out.putArray("evidenceOf");
        Map<Language, Set<String>> declaredByLanguage = Map.of(Language.PYTHON, Set.of("A03"), Language.JAVA,
                Set.of("A02", "A05"), Language.GO, Set.of());
        Object[][] evidenceCases = {
            {Observation.OK, EVERY, List.of("java", "yaml"), List.of("java", "python")},
            {Observation.OK, EVERY, List.of("go"), List.of("java")},
            {Observation.OK, EVERY, null, List.of("java")},
            {Observation.OK, EVERY, List.of("java"), null},
            {Observation.OK, null, List.of("python", "java"), List.of("java", "python", "go")},
            {Observation.LAST_SCAN_FAILED, EVERY, List.of("java"), List.of("java")},
            {Observation.NEVER_SCANNED, List.of("sast"), null, null},
            {Observation.IN_PROGRESS, List.of(), List.of("go"), List.of("go")},
            {Observation.OK, List.of(), List.of(), List.of()},
        };
        for (Object[] c : evidenceCases) {
            @SuppressWarnings("unchecked")
            List<String> examined = (List<String>) c[1];
            @SuppressWarnings("unchecked")
            List<String> detected = (List<String>) c[2];
            @SuppressWarnings("unchecked")
            List<String> rules = (List<String>) c[3];
            Evidence of = Evidence.of(new ScanTarget.Repository(1), (Observation) c[0],
                    Optional.ofNullable(examined).map(types -> types.stream()
                            .map(type -> FindingType.fromWireName(type).orElseThrow())
                            .collect(java.util.stream.Collectors.toSet())),
                    languages(detected), languages(rules), declaredByLanguage);
            ObjectNode row = evidence.addObject();
            row.put("observation", ((Observation) c[0]).name());
            row.set("examined", list(examined));
            row.set("detected", list(detected));
            row.set("sastRules", list(rules));
            row.set("examinedAfter", list(of.examined().map(types -> types.stream().sorted()
                    .map(FindingType::wireName).toList()).orElse(null)));
            row.set("analysed", list(of.analysed().map(found -> found.stream().sorted()
                    .map(Language::wireName).toList()).orElse(null)));
            row.set("codeReaches", list(of.codeReaches().map(found -> found.stream().sorted().toList()).orElse(null)));
        }
        return out;
    }

    private static Optional<Set<Language>> languages(List<String> names) {
        return Optional.ofNullable(names).map(found -> found.stream()
                .map(name -> Language.fromWireName(name).orElseThrow())
                .collect(java.util.stream.Collectors.toSet()));
    }

    @Test
    void theCweLists() {
        ObjectNode out = RustReference.object();
        ArrayNode table = out.putArray("table");
        for (int cwe = 0; cwe <= 2_000; cwe++) {
            int number = cwe;
            OwaspCwe.categoryOf(cwe).ifPresent(category -> table.addArray().add(number).add(category));
        }
        String[] declarations = {
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command", "cwe-918", "CwE-79",
            "CWE-1078, then CWE-22", "CWE-1078: Inappropriate Source Code Style", "CWE-99999999999", "ACWE-89",
            "", "CWE-89a", "CWE-89_", "_CWE-89", "éCWE-89", "CWE-89é", "CWE-0089", "CWE-٣٨",
            "CWE-2147483647", "CWE-2147483648 CWE-918", "CWE--89", "CWE-89-", "CWE 89", "CWE-", "x CWE-1 y CWE-20",
            "(CWE-200)", "CWE-259", "CWE-798", "[\"CWE-327: Use of a Broken or Risky Cryptographic Algorithm\"]",
            "CWE-８９", "KCWE-89", "CWE-89́", "😀CWE-502", "cwe-1104/CWE-937",
        };
        ArrayNode rows = out.putArray("declarations");
        for (String declaration : declarations) {
            rows.addArray().add(declaration).add(OwaspCwe.categoryOfDeclaration(declaration).orElse(null));
        }
        RustReference.expect("compliance/cwe.json", out, ComplianceReferenceSetTest.class);
    }

    @Test
    void theTrends() {
        ObjectNode out = RustReference.object();
        ArrayNode weeks = out.putArray("weeks");
        String[] instants = {
            "2026-11-16T00:00:00Z", "2026-11-15T23:59:59.999999999Z", "2026-11-17T10:00:00Z", "2026-11-22T23:59:59Z",
            "2026-11-23T00:00:00Z", "2026-01-01T12:00:00Z", "2024-02-29T05:00:00Z", "1970-01-01T00:00:00Z",
            "1969-12-28T23:00:00Z", "1900-03-01T00:00:00.5Z", "2000-01-03T00:00:00Z", "2099-12-31T23:59:59Z",
        };
        for (String instant : instants) {
            weeks.addArray().add(instant).add(CoverageWeek.startOf(Instant.parse(instant)).toString());
        }
        ArrayNode mttr = out.putArray("mttr");
        Instant base = Instant.parse("2026-08-22T10:00:00Z");
        Object[][][] cases = {
            {},
            {{"CRITICAL", 5, 0}, {"CRITICAL", 7, 0}, {"HIGH", 12, 0}, {"HIGH", 20, 0}},
            {{"LOW", 0, 0}},
            {{"LOW", -1, 0}},
            {{null, 3, 0}, {"UNKNOWN", 1, 0}, {"NEGLIGIBLE", 2, 0}, {"MEDIUM", 4, 0}},
            {{"HIGH", 1, 0}, {"HIGH", 1, 0}, {"HIGH", 2, 0}, {"HIGH", 3, 0}},
            {{"MEDIUM", 1, 0}, {"MEDIUM", 1, 0}, {"MEDIUM", 1, 0}, {"MEDIUM", 1, 0}, {"MEDIUM", 1, 0},
                {"MEDIUM", 1, 0}, {"MEDIUM", 1, 0}, {"MEDIUM", 2, 0}},
            {{"CRITICAL", null, 0}, {"CRITICAL", 2, null}, {"CRITICAL", 9, 0}},
            {{"CRITICAL", null, 0}},
            {{"LOW", 300, 0}, {"CRITICAL", 1, 0}, {"LOW", 2, 0}},
        };
        for (Object[][] c : cases) {
            List<MttrCalculator.ResolvedIssue> issues = new ArrayList<>();
            ArrayNode input = RustReference.object().arrayNode();
            for (Object[] issue : c) {
                Severity severity = issue[0] == null ? null : Severity.valueOf((String) issue[0]);
                Instant resolved = issue[2] == null ? null : base;
                // Days before the resolution, less half a second and a nanosecond, so the hours floor.
                Instant firstSeen = issue[1] == null ? null
                        : base.minusSeconds(86_400L * (Integer) issue[1]).plusMillis(500).plusNanos(1);
                issues.add(new MttrCalculator.ResolvedIssue(severity, firstSeen, resolved));
                input.addArray().add(severity == null ? null : severity.name())
                        .add(firstSeen == null ? null : firstSeen.toString())
                        .add(resolved == null ? null : resolved.toString());
            }
            ObjectNode row = mttr.addObject();
            row.set("issues", input);
            row.set("result", BUNDLE.valueToTree(MttrCalculator.calculate(issues)));
        }
        // Hours, not days, decide: 23 h 59 min is one day (the floor of one), 47 h 59 min one, 48 h two.
        ArrayNode hours = RustReference.object().arrayNode();
        List<MttrCalculator.ResolvedIssue> byHours = new ArrayList<>();
        for (long seconds : new long[] {0, 3_599, 86_399, 172_799, 172_800, 259_199}) {
            byHours.add(new MttrCalculator.ResolvedIssue(Severity.HIGH, base, base.plusSeconds(seconds)));
            hours.addArray().add("HIGH").add(base.toString()).add(base.plusSeconds(seconds).toString());
        }
        ObjectNode row = mttr.addObject();
        row.set("issues", hours);
        row.set("result", BUNDLE.valueToTree(MttrCalculator.calculate(byHours)));
        RustReference.expect("compliance/trends.json", out, ComplianceReferenceSetTest.class);
    }

    @Test
    void theSpreadsheetCells() {
        ObjectNode out = RustReference.object();
        ArrayNode rows = out.putArray("cells");
        String[] values = {
            "", "=", "=1+1", "+1", "-1", "@SUM(A1)", "\t=cmd|' /c calc'!A1", "\r=cmd", "\n=cmd", " =1", "'=1", "a=1",
            "＝1", "\u0000=", "é", "😀=", "=HYPERLINK(\"http://x\"&A1)", "-", "+", "@", "\t", "\r",
            "plain", "1-2", "−" + "1",
        };
        for (String value : values) {
            rows.addArray().add(value).add(SpreadsheetCells.neutralize(value));
        }
        RustReference.expect("compliance/cells.json", out, ComplianceReferenceSetTest.class);
    }
}
