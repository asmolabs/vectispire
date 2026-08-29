package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.AiReviewService;
import com.asmolabs.vectispire.core.services.OwaspReviewService;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The OWASP report: what it is built from, and what it says when it cannot be built.
 *
 * <p>The model is mocked throughout. What is under test is everything around the call — the
 * digest it receives, the refusals that stop it, and the row written when it fails — because
 * those are the parts that decide whether an operator can trust the page.
 */
@DisplayName("the OWASP report")
class OwaspReportTest extends ApiTestBase {

    private static final Instant NOW = Instant.parse("2026-08-21T09:00:00Z");

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private Issues issues;

    @Autowired
    private com.asmolabs.vectispire.core.repositories.AiReviewResults results;

    private AiReviewService models;
    private OwaspReviewService service;
    private RepositoryEntity repository;

    @BeforeEach
    void wire() {
        models = Mockito.mock(AiReviewService.class);
        Mockito.when(models.isEnabled()).thenReturn(true);
        Mockito.when(models.selectedModel()).thenReturn("gemma4:12b-it-qat");
        service = new OwaspReviewService(models, results, issues, scans, Clock.fixed(NOW, ZoneOffset.UTC));

        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("ssh://git@example.com/art/arm-libs-spring.git");
        entity.setName("Arm Libs Spring");
        entity.setBranch("master");
        repository = repositories.save(entity);
    }

    @Nested
    @DisplayName("when it can be built")
    class Built {

        @Test
        @DisplayName("sends the backlog as data and stores what the model answered")
        void theReportIsStored() {
            long scanId = seedScan("1.17.6");
            seedIssue(scanId);
            Mockito.when(models.reviewCode(Mockito.anyString(), Mockito.anyString()))
                    .thenReturn("## A06 — Vulnerable and Outdated Components\\nopenssl is old.");

            AiReviewResultEntity stored = service.run(repository);

            assertThat(stored.getStatus()).isEqualTo("completed");
            assertThat(stored.getModel()).isEqualTo("gemma4:12b-it-qat");
            assertThat(stored.getResponse()).contains("A06");
            // Tied to the scan, which is what dates the report and names the version it describes.
            assertThat(stored.getScanId()).isEqualTo(scanId);

            ArgumentCaptor<String> digest = ArgumentCaptor.forClass(String.class);
            Mockito.verify(models).reviewCode(digest.capture(), Mockito.anyString());
            assertThat(digest.getValue()).contains("CVE-2026-1234");
            assertThat(digest.getValue()).contains("Project version: 1.17.6");
        }

        @Test
        @DisplayName("records the failure instead of losing the attempt")
        void aFailedModelCallIsRecorded() {
            seedScan("1.17.6");
            Mockito.when(models.reviewCode(Mockito.anyString(), Mockito.anyString()))
                    .thenThrow(new IllegalStateException("Connection refused to http://localhost:11434"));

            AiReviewResultEntity stored = service.run(repository);

            // "The model could not be reached at 09:00" is what belongs on the screen. A run that
            // vanished would leave the page identical to one nobody ever asked for.
            assertThat(stored.getStatus()).isEqualTo("failed");
            assertThat(stored.getError()).contains("Connection refused");
            assertThat(service.latest(repository.getId())).get().extracting(AiReviewResultEntity::getStatus)
                    .isEqualTo("failed");
        }
    }

    @Nested
    @DisplayName("when it cannot")
    class Refused {

        @Test
        @DisplayName("a never-scanned repository is refused rather than reported on")
        void noScanNoReport() {
            // The trap the posture PDF names, in a format that reads even more like a verdict: a
            // target nobody scanned has an empty backlog, and a report over an empty backlog is a
            // clean bill of health for something nothing looked at.
            assertThat(org.assertj.core.api.Assertions.catchThrowable(() -> service.run(repository)))
                    .isInstanceOf(OwaspReviewService.ReviewRefusedException.class)
                    .hasMessageContaining("never been scanned");

            Mockito.verify(models, Mockito.never()).reviewCode(Mockito.anyString(), Mockito.anyString());
        }

        @Test
        @DisplayName("a disabled model review is refused before anything reaches the network")
        void disabledIsRefused() {
            Mockito.when(models.isEnabled()).thenReturn(false);
            seedScan("1.17.6");

            assertThat(org.assertj.core.api.Assertions.catchThrowable(() -> service.run(repository)))
                    .isInstanceOf(OwaspReviewService.ReviewRefusedException.class)
                    .hasMessageContaining("switched off");

            Mockito.verify(models, Mockito.never()).reviewCode(Mockito.anyString(), Mockito.anyString());
        }
    }

    private long seedScan(String version) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repository.getId());
        scan.setBranch("master");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(NOW.minusSeconds(3600));
        scan.setVersion(version);
        return scans.save(scan).getId();
    }

    private void seedIssue(long scanId) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repository.getId());
        issue.setFingerprint("fp-CVE-2026-1234");
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-1234");
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setPackageName("openssl");
        issue.setPackageVersion("3.0.1");
        issue.setFirstSeenAt(NOW);
        issue.setLastSeenAt(NOW);
        issue.setLastSeenScanId(scanId);
        issue.setTimesSeen(1);
        issues.save(issue);
    }

    @Test
    @DisplayName("the PDF export returns a document, not an empty file")
    void theExportReturnsBytes() throws Exception {
        long scanId = seedScan("1.17.6");
        AiReviewResultEntity stored = new AiReviewResultEntity();
        stored.setScanId(scanId);
        stored.setModel("gemma4:e4b");
        stored.setPrompt("p");
        stored.setResponse("## A03 — Injection\n\nA finding worth reporting.");
        stored.setStatus("completed");
        stored.setCreatedAt(NOW);
        results.save(stored);

        byte[] pdf = mvc.perform(authenticated(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                .get("/api/v1/repositories/" + repository.getId() + "/owasp-review/export.pdf"),
                        asAdmin()))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsByteArray();

        // The assertion that a 0-byte download would have caught: bytes, and a PDF's own header.
        assertThat(pdf).isNotEmpty();
        assertThat(new String(pdf, 0, 5, java.nio.charset.StandardCharsets.ISO_8859_1)).isEqualTo("%PDF-");
    }

    @Test
    @DisplayName("the connection-test route is reachable by any account")
    void theRouteAnswers() throws Exception {
        // The branch logic is unit-tested below; this asserts the far duller thing that was
        // missing and that no unit test can see — that the route exists, is mapped to POST, and
        // is not narrowed to a role the person clicking the button may not have.
        mvc.perform(authenticated(post("/api/v1/settings/ollama-test"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detail").isString());
    }

    @Nested
    @DisplayName("the Ollama connection test")
    class OllamaCheck {

        /**
         * <b>Both branches, against a mocked service, because the real one depends on the
         * machine.</b> A first version asserted "unreachable" over the live host and failed on a
         * developer who happened to be running Ollama — a test that passes or fails on what is
         * installed says nothing about the code.
         */
        private SettingsController controllerWith(List<String> models) {
            AiReviewService ai = Mockito.mock(AiReviewService.class);
            Mockito.when(ai.selectedModel()).thenReturn("gemma4:12b-it-qat");
            Mockito.when(ai.validatedUrl()).thenReturn("http://localhost:11434");
            Mockito.when(ai.availableModels()).thenReturn(models);
            // Stubbed rather than left to Mockito's null: the check names the provider in the
            // sentence it returns, and these cases are about the Ollama one.
            Mockito.when(ai.provider())
                    .thenReturn(com.asmolabs.vectispire.common.domain.aireview.AiProvider.OLLAMA);
            return new SettingsController(
                    Mockito.mock(com.asmolabs.vectispire.core.services.SettingsService.class),
                    Mockito.mock(com.asmolabs.vectispire.core.services.TicketService.class),
                    Mockito.mock(com.asmolabs.vectispire.core.services.AuditLogService.class),
                    ai,
                    Mockito.mock(com.asmolabs.vectispire.core.services.NotificationService.class));
        }

        @Test
        @DisplayName("the fallback suggestions are not an answer from the host")
        void suggestionsMeanUnreachable() {
            // `availableModels` never throws and returns suggestions when nothing answered —
            // right for a dropdown, and indistinguishable from success unless the check says so.
            var check = controllerWith(com.asmolabs.vectispire.common.domain.aireview.AiReview.FALLBACK_MODEL_SUGGESTIONS)
                    .testOllama();

            assertThat(check.reachable()).isFalse();
            assertThat(check.detail()).contains("Is Ollama running");
        }

        @Test
        @DisplayName("reachable without the model is its own answer, not a green tick")
        void reachableButNotInstalled() {
            // The commonest misconfiguration. A single boolean would hide it until the first
            // report failed, on another screen, minutes later.
            var check = controllerWith(List.of("llama3:8b", "qwen2:7b")).testOllama();

            assertThat(check.reachable()).isTrue();
            assertThat(check.modelInstalled()).isFalse();
            // "available" rather than "installed": nothing is installed on a hosted API, and one
            // sentence now serves both providers.
            assertThat(check.detail()).contains("is not available there");
        }

        @Test
        @DisplayName("reachable with the model says so plainly")
        void reachableAndInstalled() {
            var check = controllerWith(List.of("gemma4:12b-it-qat", "llama3:8b")).testOllama();

            assertThat(check.reachable()).isTrue();
            assertThat(check.modelInstalled()).isTrue();
        }
    }
}
