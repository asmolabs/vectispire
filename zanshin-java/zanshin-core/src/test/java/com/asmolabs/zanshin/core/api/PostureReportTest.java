package com.asmolabs.zanshin.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import java.time.Instant;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * The posture report, read back rather than merely produced.
 *
 * <p>Asserting the response is 200 and non-empty would pass on a corrupt file. These tests parse
 * the bytes with the same library that wrote them and read the words out, because "the endpoint
 * returned something" and "somebody can open it" are different claims.
 */
@DisplayName("the posture report")
class PostureReportTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private com.asmolabs.zanshin.core.repositories.Issues issues;

    @Test
    @DisplayName("is a PDF that names the target, its verdict and its findings")
    void theReportReadsBack() throws Exception {
        long id = seedRepository();
        seedIssue(id, Severity.HIGH, "CVE-2026-1234", "openssl");

        byte[] pdf = mvc.perform(authenticated(get("/api/v1/targets/repository/" + id + "/posture.pdf"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PDF))
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"zanshin-repository-" + id + ".pdf\""))
                .andReturn()
                .getResponse()
                .getContentAsByteArray();

        String text = textOf(pdf);
        assertThat(text).contains("Zanshin — security posture");
        assertThat(text).contains("org/project");
        assertThat(text).contains("CVE-2026-1234");
        assertThat(text).contains("openssl");
    }

    @Test
    @DisplayName("says a never-scanned target was not observed, next to its verdict")
    void anUnobservedTargetSaysSo() throws Exception {
        long id = seedRepository();

        String text = textOf(mvc.perform(
                        authenticated(get("/api/v1/targets/repository/" + id + "/posture.pdf"), asAdmin()))
                .andReturn()
                .getResponse()
                .getContentAsByteArray());

        // The document outlives the screen and gets forwarded. "PASSING" alone on a target
        // nobody scanned turns the absence of a scan into a clean bill of health, and the
        // reader has no way to know an empty backlog satisfies every policy.
        assertThat(text).contains("NOT OBSERVED");
        assertThat(text).contains("not because nothing is there");
    }

    @Test
    @DisplayName("the OpenVEX export downloads rather than rendering in the tab")
    void vexIsAnAttachment() throws Exception {
        long id = seedRepository();

        mvc.perform(authenticated(get("/api/v1/targets/repository/" + id + "/vex"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(header().string(
                        "Content-Disposition", "attachment; filename=\"zanshin-repository-" + id + ".openvex.json\""));
    }

    private static String textOf(byte[] pdf) throws Exception {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            return new PDFTextStripper().getText(document);
        }
    }

    private void seedIssue(long repositoryId, Severity severity, String identifier, String packageName) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repositoryId);
        issue.setFingerprint("fp-" + identifier);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(severity.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setPackageName(packageName);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }

    private long seedRepository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://github.com/org/project.git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }
}
