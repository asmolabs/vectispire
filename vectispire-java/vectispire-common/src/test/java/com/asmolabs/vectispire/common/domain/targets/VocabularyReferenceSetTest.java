package com.asmolabs.vectispire.common.domain.targets;

import com.asmolabs.vectispire.common.domain.dependencies.DependencyGraph;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.licenses.LicenseBlocklist;
import com.asmolabs.vectispire.common.domain.retention.EvidenceRetention;
import com.asmolabs.vectispire.common.domain.retention.RetentionPolicy;
import com.asmolabs.vectispire.common.domain.sbom.Sbom;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.SplittableRandom;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The target and scan vocabulary the Rust control plane's {@code domain} crate is held to: what the finding
 * types and scan statuses are called and do, what an SBOM is read as ({@link Sbom}, {@link DependencyGraph},
 * {@link LicenseBlocklist}), and which raw payloads retention purges.
 *
 * <p><b>The SBOM readers are where Jackson's leniency becomes data.</b> {@code asText(null)} turns a number or
 * a boolean into its text and an object into the empty string; {@code Sbom.text} only takes a string, trimmed
 * with {@code String.trim}. A port reading the same document through serde has to make each of those choices
 * the same way, or a dependency's directness — the field an operator ranks a backlog by — and a forbidden
 * licence's presence follow the parser rather than the document. {@code sboms.json} holds the documents; the
 * answers are this side's.
 */
class VocabularyReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void theSbomReadings() throws Exception {
        JsonNode inputs = JSON.readTree(ReferenceSet.read("vocabulary/sboms.json"));
        ArrayNode answers = JSON.createArrayNode();
        for (JsonNode input : inputs) {
            JsonNode document = input.get("document");
            ObjectNode answer = answers.addObject();
            answer.put("name", input.path("name").asText());
            answer.put("is_catalogue", Sbom.isCatalogue(document));

            Sbom sbom = new Sbom(document);
            ArrayNode artifacts = answer.putArray("artifacts");
            for (Sbom.Artifact artifact : sbom.artifacts()) {
                ObjectNode a = artifacts.addObject();
                a.put("name", artifact.name());
                a.put("version", artifact.version());
                a.put("purl", artifact.purl());
                ArrayNode licenses = a.putArray("licenses");
                artifact.licenses().forEach(licenses::add);
            }
            sbom.distro().ifPresentOrElse(distro -> answer.putObject("distro")
                    .put("id", distro.id())
                    .put("version", distro.version())
                    .put("label", distro.label()), () -> answer.putNull("distro"));

            DependencyGraph graph = new DependencyGraph(document);
            answer.put("graph_available", graph.isAvailable());
            answer.put("direct_count", graph.directCount());
            ArrayNode probes = answer.putArray("probes");
            for (JsonNode probe : input.path("probes")) {
                probes.add(graph.of(text(probe.get(0)), text(probe.get(1)), text(probe.get(2))).name());
            }

            if (input.has("blocklist")) {
                ArrayNode violations = answer.putArray("violations");
                for (LicenseBlocklist.Violation v : LicenseBlocklist.parse(input.get("blocklist").asText()).violations(sbom)) {
                    violations.addObject()
                            .put("license", v.license())
                            .put("package_name", v.packageName())
                            .put("package_version", v.packageVersion())
                            .put("purl", v.purl());
                }
            }
        }
        ReferenceSet.expect("vocabulary/sbom-answers.json", JSON.writeValueAsString(answers) + "\n");
    }

    @Test
    void theWordsAndTheRules() throws Exception {
        ObjectNode out = JSON.createObjectNode();

        ArrayNode types = out.putArray("finding_types");
        for (FindingType type : FindingType.values()) {
            types.addObject()
                    .put("wire_name", type.wireName())
                    .put("gate", type.gateParticipation().name())
                    .put("tool_scoped", type.toolScoped())
                    .put("security", type.isSecurity());
        }
        ArrayNode statuses = out.putArray("scan_statuses");
        for (ScanStatus status : ScanStatus.values()) {
            statuses.addObject().put("wire_name", status.wireName()).put("in_flight", status.isInFlight());
        }
        String[] probes = {null, "", "sast", "SAST", " sast", "ai_review", "ai-review", "imported", "plugin ",
            "pending", "PENDING", " Completed\t", "failed ", "scanning\u001F", "\u0085failed", "complete"};
        ArrayNode wire = out.putArray("from_wire_name");
        for (String probe : probes) {
            wire.addObject()
                    .put("value", probe)
                    .put("finding_type", FindingType.fromWireName(probe).map(FindingType::wireName).orElse(null))
                    .put("scan_status", ScanStatus.fromWireName(probe).map(ScanStatus::wireName).orElse(null));
        }

        ArrayNode blocklists = out.putArray("blocklists");
        for (String raw : new String[] {null, "", "  ", ",", "MIT", " mit , Apache-2.0,, mit ", "gpl-3.0 ", "\tbsd\n", "ß", "ı,i"}) {
            ArrayNode forbidden = JSON.createArrayNode();
            new TreeSet<>(LicenseBlocklist.parse(raw).forbidden()).forEach(forbidden::add);
            blocklists.addObject().put("raw", raw).set("forbidden", forbidden);
        }

        ArrayNode settings = out.putArray("int_settings");
        for (String raw : new String[] {null, "", " ", "0", "7", " 12 ", "-1", "-0", "+5", "007", "2147483647", "2147483648",
            "1e3", "1.5", "abc", "٣", "５", " 5", "5\u001F", "0x10"}) {
            settings.addObject().put("raw", raw).put("value", RetentionPolicy.intSetting(raw, 90));
        }

        // Character.digit(char, 10), which Integer.parseInt reads: the zero of every run of ten digits.
        ArrayNode zeros = out.putArray("digit_zeros");
        for (int c = 0; c <= Character.MAX_VALUE; c++) {
            if (Character.digit((char) c, 10) == 0) {
                zeros.add(c);
            }
            if (Character.digit((char) c, 10) > 0 && Character.digit((char) (c - 1), 10) != Character.digit((char) c, 10) - 1) {
                zeros.add("not a run at " + c);
            }
        }

        Instant now = Instant.parse("2026-10-17T12:00:00.500Z");
        ArrayNode evidence = out.putArray("evidence_cutoffs");
        for (int days : new int[] {-5, 0, 1, 400}) {
            ObjectNode e = evidence.addObject().put("days", days);
            EvidenceRetention.cutoff(days, now).ifPresentOrElse(cutoff -> e.set("cutoff", instant(cutoff)), () -> e.putNull("cutoff"));
        }

        out.set("retention", retention(now));
        ReferenceSet.expect("vocabulary/answers.json", JSON.writeValueAsString(out) + "\n");
    }

    /**
     * {@link RetentionPolicy#prunable} over generated histories — several targets of both kinds, interleaved
     * as the caller's query returns them (newest first, target by target), with scans on both sides of the
     * cut-off and exactly on it — for policies limited on one axis, the other, both, and neither.
     */
    private static ArrayNode retention(Instant now) {
        SplittableRandom random = new SplittableRandom(24);
        ArrayNode cases = JSON.createArrayNode();
        int[][] policies = {{10, 90}, {0, 90}, {3, 0}, {0, 0}, {1, 1}, {2, 30}};
        for (int[] policy : policies) {
            for (int run = 0; run < 3; run++) {
                RetentionPolicy retention = new RetentionPolicy(policy[0], Duration.ofDays(policy[1]));
                List<RetentionPolicy.Candidate> candidates = new ArrayList<>();
                long scanId = 1;
                for (int t = 0; t < 4; t++) {
                    ScanTarget target = t % 2 == 0 ? new ScanTarget.Repository(t / 2) : new ScanTarget.Container(t / 2);
                    Instant at = now;
                    int count = random.nextInt(15);
                    for (int s = 0; s < count; s++) {
                        candidates.add(new RetentionPolicy.Candidate(scanId++, target, at));
                        at = random.nextInt(5) == 0 && policy[1] > 0
                                ? now.minus(Duration.ofDays(policy[1]))
                                : at.minusSeconds(random.nextInt(40 * 86_400));
                    }
                }
                ObjectNode c = cases.addObject();
                c.put("keep_per_target", policy[0]);
                c.put("max_age_days", policy[1]);
                c.set("now", instant(now));
                c.put("enabled", retention.isEnabled());
                ArrayNode list = c.putArray("candidates");
                for (RetentionPolicy.Candidate candidate : candidates) {
                    ObjectNode n = list.addObject();
                    n.put("scan_id", candidate.scanId());
                    switch (candidate.target()) {
                        case ScanTarget.Repository r -> n.put("repository", r.id());
                        case ScanTarget.Container k -> n.put("container", k.id());
                    }
                    n.set("created_at", instant(candidate.createdAt()));
                }
                ArrayNode prunable = c.putArray("prunable");
                retention.prunable(candidates, now).forEach(prunable::add);
            }
        }
        return cases;
    }

    private static ObjectNode instant(Instant value) {
        return JSON.createObjectNode().put("epoch_second", value.getEpochSecond()).put("nano", value.getNano());
    }

    private static String text(JsonNode node) {
        return node == null || node.isNull() ? null : node.asText();
    }
}
