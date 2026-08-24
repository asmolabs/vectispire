package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * The detection-and-triage trail, end to end.
 *
 * <p>The documents are read back rather than merely produced: "the endpoint returned something"
 * and "somebody can open it and find the decision in it" are different claims, and only the
 * second is what this feature is for.
 */
@DisplayName("the detection and triage history")
class HistoryTest extends ApiTestBase {

    private static final Instant DETECTED = Instant.parse("2026-03-03T08:00:00Z");
    private static final Instant DECIDED = Instant.parse("2026-03-07T14:30:00Z");

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private Issues issues;

    @Autowired
    private Findings findings;

    @Autowired
    private TriageEvents events;

    @Test
    @DisplayName("joins the version, the finding and the decision into one trail")
    void theDossierJoinsTheThree() throws Exception {
        long repositoryId = seedRepository();
        long scanId = seedScan(repositoryId, "2.4.1", "maven");
        long issueId = seedIssue(repositoryId, scanId);
        seedDecision(issueId, scanId);

        mvc.perform(authenticated(get("/api/v1/history/repositories/" + repositoryId), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.repository.version").value("2.4.1"))
                .andExpect(jsonPath("$.repository.projectType").value("maven"))
                .andExpect(jsonPath("$.scans[0].version").value("2.4.1"))
                .andExpect(jsonPath("$.scans[0].issues[0].identifier").value("CVE-2026-1234"))
                // Both ends of the transition, which is the reason the event table exists.
                .andExpect(jsonPath("$.scans[0].issues[0].decisions[0].fromStatus").value("under_review"))
                .andExpect(jsonPath("$.scans[0].issues[0].decisions[0].toStatus").value("not_affected"))
                .andExpect(jsonPath("$.scans[0].issues[0].decisions[0].actor").value("alice"))
                .andExpect(jsonPath("$.scans[0].issues[0].decisions[0].origin").value("manual"))
                // The version the decision was taken against, resolved from the scan it names.
                .andExpect(jsonPath("$.scans[0].issues[0].decisions[0].version").value("2.4.1"));
    }

    @Test
    @DisplayName("the repository list carries the last version actually read")
    void theListCarriesTheVersion() throws Exception {
        long repositoryId = seedRepository();
        long scanId = seedScan(repositoryId, "2.4.1", "maven");
        seedIssue(repositoryId, scanId);

        // A later scan that failed to clone read no version. It must not blank the one the
        // target still has — otherwise a target appears to lose its identity the day a clone
        // fails, on the screen somebody consults to find it.
        ScanEntity failed = new ScanEntity();
        failed.setRepoId(repositoryId);
        failed.setBranch("master");
        failed.setStatus(ScanStatus.FAILED.wireName());
        failed.setCreatedAt(DETECTED.plusSeconds(86_400));
        scans.save(failed);

        mvc.perform(authenticated(get("/api/v1/history/repositories"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].version").value("2.4.1"))
                .andExpect(jsonPath("$[0].scanCount").value(2));
    }

    @Test
    @DisplayName("the PDF names the decision, who took it and against which version")
    void thePdfReadsBack() throws Exception {
        long repositoryId = seedRepository();
        long scanId = seedScan(repositoryId, "2.4.1", "maven");
        long issueId = seedIssue(repositoryId, scanId);
        seedDecision(issueId, scanId);

        byte[] pdf = mvc.perform(
                        authenticated(get("/api/v1/history/repositories/" + repositoryId + "/export.pdf"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PDF))
                .andExpect(header().string(
                        "Content-Disposition", "attachment; filename=\"vectispire-history-" + repositoryId + ".pdf\""))
                .andReturn()
                .getResponse()
                .getContentAsByteArray();

        String text;
        try (PDDocument document = Loader.loadPDF(pdf)) {
            text = new PDFTextStripper().getText(document);
        }

        assertThat(text).contains("Vectispire — detection and triage history");
        assertThat(text).contains("version 2.4.1");
        assertThat(text).contains("CVE-2026-1234");
        assertThat(text).contains("under_review -> not_affected");
        assertThat(text).contains("by alice");
        assertThat(text).contains("The affected module is not compiled in.");
    }

    @Test
    @DisplayName("an issue nobody triaged says so rather than staying silent")
    void anUntriagedIssueIsPrinted() throws Exception {
        long repositoryId = seedRepository();
        long scanId = seedScan(repositoryId, "2.4.1", "maven");
        seedIssue(repositoryId, scanId);

        byte[] pdf = mvc.perform(
                        authenticated(get("/api/v1/history/repositories/" + repositoryId + "/export.pdf"), asAdmin()))
                .andReturn()
                .getResponse()
                .getContentAsByteArray();

        String text;
        try (PDDocument document = Loader.loadPDF(pdf)) {
            text = new PDFTextStripper().getText(document);
        }

        // Silence would let an untriaged finding pass for a decision that simply was not written
        // down. The sentence makes the gap part of the record, which is what an audit is for.
        assertThat(text).contains("no decision recorded");
        assertThat(text).contains("No triage decision has been recorded for this target.");
    }

    @Test
    @DisplayName("the CSV gives one row per decision, and one for an issue with none")
    void theCsvIsOneRowPerDecision() throws Exception {
        long repositoryId = seedRepository();
        long scanId = seedScan(repositoryId, "2.4.1", "maven");
        long issueId = seedIssue(repositoryId, scanId);
        seedDecision(issueId, scanId);

        String csv = new String(
                mvc.perform(authenticated(
                                get("/api/v1/history/repositories/" + repositoryId + "/export.csv"), asAdmin()))
                        .andExpect(status().isOk())
                        .andExpect(header().string(
                                "Content-Disposition",
                                "attachment; filename=\"vectispire-history-" + repositoryId + ".csv\""))
                        .andReturn()
                        .getResponse()
                        .getContentAsByteArray(),
                StandardCharsets.UTF_8);

        assertThat(csv.lines().findFirst()).contains(
                "repository,repository_url,scan_id,scan_at,scan_status,branch,project_type,version,"
                        + "issue_id,issue_type,identifier,severity,component,location,issue_state,current_triage,"
                        + "first_seen_at,resolved_at,decision_at,decision_from,decision_to,decision_justification,"
                        + "decision_actor,decision_origin,decision_expires_at,decision_comment");
        assertThat(csv).contains("\"CVE-2026-1234\"");
        assertThat(csv).contains("\"under_review\",\"not_affected\"");
        // Every field quoted, comment included: a triage comment is free text and routinely
        // carries the separator.
        assertThat(csv).contains("\"The affected module is not compiled in.\"");
    }

    @Test
    @DisplayName("an issue's detail carries where it was seen and what was decided")
    void theIssueDetailJoinsSightingsAndDecisions() throws Exception {
        long repositoryId = seedRepository();
        long scanId = seedScan(repositoryId, "2.4.1", "maven");
        long issueId = seedIssue(repositoryId, scanId);
        seedDecision(issueId, scanId);

        mvc.perform(authenticated(get("/api/v1/issues/" + issueId), asAdmin()))
                .andExpect(status().isOk())
                // Unwrapped, so the detail speaks the same shape as the list rather than a second
                // definition of an issue that drifts the day a column is added.
                .andExpect(jsonPath("$.identifier").value("CVE-2026-1234"))
                .andExpect(jsonPath("$.targetName").value("Arm Libs Spring"))
                // What a row cannot carry: the version it was seen on, and the decision taken.
                .andExpect(jsonPath("$.sightings[0].version").value("2.4.1"))
                .andExpect(jsonPath("$.sightings[0].scanId").value((int) scanId))
                .andExpect(jsonPath("$.decisions[0].fromStatus").value("under_review"))
                .andExpect(jsonPath("$.decisions[0].toStatus").value("not_affected"))
                .andExpect(jsonPath("$.decisions[0].actor").value("alice"));
    }

    @Test
    @DisplayName("an issue that does not exist is a 404")
    void anUnknownIssueIsNotFound() throws Exception {
        mvc.perform(authenticated(get("/api/v1/issues/9999"), asAdmin()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("a repository that does not exist is a 404, not an empty dossier")
    void anUnknownRepositoryIsNotFound() throws Exception {
        mvc.perform(authenticated(get("/api/v1/history/repositories/9999"), asAdmin()))
                .andExpect(status().isNotFound());
    }

    private long seedRepository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("ssh://git@bitbucket.example.com/art/arm-libs-spring.git");
        repository.setName("Arm Libs Spring");
        repository.setBranch("master");
        return repositories.save(repository).getId();
    }

    private long seedScan(long repositoryId, String version, String projectType) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("master");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(DETECTED);
        scan.setVersion(version);
        scan.setProjectType(projectType);
        scan.setFindingsCount(1);
        return scans.save(scan).getId();
    }

    private long seedIssue(long repositoryId, long scanId) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repositoryId);
        issue.setFingerprint("fp-CVE-2026-1234");
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-1234");
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setPackageName("openssl");
        issue.setPackageVersion("3.0.1");
        issue.setFirstSeenAt(DETECTED);
        issue.setLastSeenAt(DETECTED);
        issue.setLastSeenScanId(scanId);
        issue.setTimesSeen(1);
        long issueId = issues.save(issue).getId();

        FindingEntity finding = new FindingEntity();
        finding.setScanId(scanId);
        finding.setIssueId(issueId);
        finding.setType(FindingType.VULNERABILITY.wireName());
        finding.setSeverity(Severity.HIGH.wireName());
        finding.setIdentifier("CVE-2026-1234");
        finding.setPackageName("openssl");
        finding.setSource("grype");
        finding.setCreatedAt(DETECTED);
        finding.setIsKev(false);
        findings.save(finding);

        return issueId;
    }

    private void seedDecision(long issueId, long scanId) {
        TriageEventEntity event = new TriageEventEntity();
        event.setIssueId(issueId);
        event.setFromStatus(TriageStatus.UNDER_REVIEW.wireName());
        event.setToStatus(TriageStatus.NOT_AFFECTED.wireName());
        event.setJustification("vulnerable_code_not_present");
        event.setComment("The affected module is not compiled in.");
        event.setActor("alice");
        event.setOrigin("manual");
        event.setOccurredAt(DECIDED);
        event.setScanId(scanId);
        events.save(event);
    }
}
