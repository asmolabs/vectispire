package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Applicability;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.EvidenceSource;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Implementation;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.compliance.ComplianceHistoryService;
import com.asmolabs.vectispire.core.compliance.StatementOfApplicabilityService;
import com.asmolabs.vectispire.core.compliance.persistence.ComplianceSnapshotRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * What the compliance routes say of an estate nobody has scanned.
 *
 * <p><b>They said "compliant".</b> On an instance with no scan at all the statement of applicability
 * measured ISO 27001's A.8.28, A.8.9 and A.5.15 compliant on zero findings nobody had looked for, and
 * A.8.8 non-compliant on "1 target(s) have never been scanned" — with no target registered. Decision
 * 0007 says absent is not empty; the routes now say {@code NO_DATA}, the SoA sets a declaration
 * against it as {@code UNEVIDENCED}, and the monthly capture writes nothing. Pinned on the wire,
 * because the values are what the screen and an integration read.
 */
@DisplayName("the compliance routes on an estate with no scan")
class ComplianceNoDataRoutesTest extends ApiTestBase {

    private static final String VULN = "ISO-A.8.8";

    @Autowired
    private StatementOfApplicabilityService soa;

    @Autowired
    private ComplianceHistoryService history;

    @Autowired
    private ComplianceSnapshotRepository snapshots;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    private JsonNode read(String path) throws Exception {
        return json.readTree(mvc.perform(authenticated(get(path), asAdmin()))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString());
    }

    private void declareImplemented(String controlId) {
        soa.declare(ComplianceFramework.ISO_27001, controlId, new StatementOfApplicabilityService.Submission(
                Applicability.APPLICABLE, "In scope.", Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE, null,
                "n.faure", null), "c.moreau");
    }

    private long scannedRepository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/clean.git");
        repository.setName("clean");
        repository.setBranch("main");
        long id = repositories.save(repository).getId();
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(id);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now());
        scans.save(scan);
        return id;
    }

    private static List<String> texts(JsonNode array, String field) {
        List<String> values = new ArrayList<>();
        array.forEach(element -> values.add(element.get(field).asText()));
        return values;
    }

    @Test
    @DisplayName("measures no ISO 27001 control, and a declaration set against nothing is unevidenced, not consistent")
    void theStatementMeasuresNothing() throws Exception {
        declareImplemented(VULN);

        JsonNode statement = read("/api/v1/compliance/soa/ISO_27001");

        assertThat(texts(statement.get("lines"), "measured"))
                .as("A.8.8 read NON_COMPLIANT and the other three COMPLIANT, with no scan at all")
                .hasSize(4)
                .containsOnly("NO_DATA");
        for (JsonNode line : statement.get("lines")) {
            if (line.get("control").get("id").asText().equals(VULN)) {
                assertThat(line.get("divergence").asText()).isEqualTo("UNEVIDENCED");
            }
        }

        for (JsonNode evaluation : read("/api/v1/compliance/summary").get("evaluations")) {
            if (evaluation.get("framework").asText().equals("ISO_27001")) {
                assertThat(texts(evaluation.get("controls"), "details"))
                        .as("the count as it is: the service handed the engine one target to divide by, "
                                + "and the engine said it had never been scanned")
                        .allMatch(details -> details.startsWith("No target is registered"));
            }
        }
    }

    @Test
    @DisplayName("reads every framework as no data on the summary, and a registered, unscanned target as no data in the matrix")
    void theSummaryMeasuresNothing() throws Exception {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/unscanned.git");
        repository.setBranch("main");
        repositories.save(repository);

        JsonNode summary = read("/api/v1/compliance/summary");

        assertThat(texts(summary.get("evaluations"), "overallStatus")).containsOnly("NO_DATA");
        assertThat(summary.get("targets")).hasSize(1);
        JsonNode target = summary.get("targets").get(0);
        assertThat(target.get("overallStatus").asText()).isEqualTo("NO_DATA");
        assertThat(target.get("frameworkScores").size())
                .as("no framework was measured on it, so none has a score to show")
                .isZero();
    }

    @Test
    @DisplayName("captures no month for a framework with nothing measured")
    void theCaptureWritesNothing() {
        assertThat(history.capture()).isZero();
        assertThat(snapshots.findAll()).isEmpty();
    }

    @Test
    @DisplayName("measures a scanned, clean estate as before: compliant, and consistent with a declaration")
    void aScannedEstateIsMeasured() throws Exception {
        scannedRepository();
        declareImplemented(VULN);

        JsonNode statement = read("/api/v1/compliance/soa/ISO_27001");

        assertThat(texts(statement.get("lines"), "measured")).doesNotContain("NO_DATA");
        for (JsonNode line : statement.get("lines")) {
            if (line.get("control").get("id").asText().equals(VULN)) {
                assertThat(line.get("measured").asText()).isEqualTo("COMPLIANT");
                assertThat(line.get("divergence").asText()).isEqualTo("CONSISTENT");
            }
        }
        assertThat(history.capture()).as("every framework has a verdict to capture").isPositive();
    }
}
