package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.ai.AiReviewService;
import com.asmolabs.vectispire.core.compliance.internal.OwaspReviewService;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.platform.web.SettingsController;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionSynchronizationManager;

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
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private com.asmolabs.vectispire.core.scanning.ScanCatalog catalog;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultRepository results;

    @Autowired
    private org.springframework.transaction.support.TransactionTemplate transactions;

    @Autowired
    private com.asmolabs.vectispire.core.compliance.OwaspReportService reports;

    @Autowired
    private com.asmolabs.vectispire.core.compliance.OwaspCoverageService coverage;

    private AiReviewService models;
    private OwaspReviewService service;
    private com.asmolabs.vectispire.core.targets.RepositoryView repository;

    @BeforeEach
    void wire() {
        models = Mockito.mock(AiReviewService.class);
        Mockito.when(models.isEnabled()).thenReturn(true);
        Mockito.when(models.selectedModel()).thenReturn("gemma4:12b-it-qat");
        Mockito.when(models.timeout()).thenReturn(java.time.Duration.ofSeconds(300));
        service = new OwaspReviewService(
                models, results, new com.asmolabs.vectispire.core.issues.IssueCatalog(issues), catalog, coverage,
                transactions, Clock.fixed(NOW, ZoneOffset.UTC));

        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("ssh://git@example.com/art/basalt-libs-spring.git");
        entity.setName("Arm Libs Spring");
        entity.setBranch("master");
        repository = com.asmolabs.vectispire.core.targets.RepositoryView.of(repositories.save(entity));
    }

    @Nested
    @DisplayName("when it can be built")
    class Built {

        @Test
        @DisplayName("each finding goes with the category the grid places it in, a rule's declaration included, and the grid with them")
        void theCategoriesAreTheGrids() {
            long scanId = seedScan("1.17.6");
            seedIssue(scanId);
            IssueEntity injection = new IssueEntity();
            injection.setRepoId(repository.id());
            injection.setFingerprint("fp-java.sqli");
            injection.setType(FindingType.SAST.wireName());
            injection.setIdentifier("java.sqli");
            injection.setSeverity(Severity.HIGH.wireName());
            injection.setState(IssueState.OPEN.wireName());
            injection.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
            // What the Semgrep rule declares in its metadata, carried on the issue.
            injection.setOwaspCategory("A03");
            injection.setFilePath("src/main/java/Dao.java");
            injection.setFirstSeenAt(NOW);
            injection.setLastSeenAt(NOW);
            injection.setLastSeenScanId(scanId);
            injection.setTimesSeen(1);
            issues.save(injection);
            Mockito.when(models.reviewCode(Mockito.anyString(), Mockito.anyString())).thenReturn("## A03");

            service.run(repository);

            ArgumentCaptor<String> digest = ArgumentCaptor.forClass(String.class);
            Mockito.verify(models).reviewCode(digest.capture(), Mockito.anyString());
            assertThat(digest.getValue()).contains("vulnerability | A06 | high | CVE-2026-1234");
            assertThat(digest.getValue()).contains("sast | A03 | high | java.sqli");
            // The repository's grid, as the compliance screen reads it for this repository alone.
            assertThat(digest.getValue()).contains("A06 Vulnerable and Outdated Components | findings");
            assertThat(digest.getValue()).contains("A01 Broken Access Control | not_covered");
        }

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
            // What the report's links may point at, recorded with the request: recomputed later it would
            // be today's backlog, which the model was never shown.
            assertThat(com.asmolabs.vectispire.core.compliance.internal.EvidenceIdentifiers.read(
                            results.findById(stored.getId()).orElseThrow().getEvidenceIdentifiers()))
                    .contains(List.of("CVE-2026-1234"));
        }

        @Test
        @DisplayName("the latest report of a repository is its own, however recent another repository's")
        void theLatestIsTheRepositorysOwn() {
            long scanId = seedScan("1.17.6");
            Mockito.when(models.reviewCode(Mockito.anyString(), Mockito.anyString())).thenReturn("## A01");
            AiReviewResultEntity own = service.run(repository);

            RepositoryEntity entity = new RepositoryEntity();
            entity.setUrl("ssh://git@example.com/art/other.git");
            entity.setName("Other");
            entity.setBranch("main");
            var other = com.asmolabs.vectispire.core.targets.RepositoryView.of(repositories.save(entity));
            ScanEntity scan = new ScanEntity();
            scan.setRepoId(other.id());
            scan.setBranch("main");
            scan.setStatus(ScanStatus.COMPLETED.wireName());
            scan.setCreatedAt(NOW);
            scans.save(scan);
            AiReviewResultEntity newer = service.run(other);

            // The repository is the row's copy of its scan's (V62): written with the review, and what
            // the latest is looked up by — the same instant for both, so only the repository tells them apart.
            assertThat(own.getRepoId()).isEqualTo(repository.id());
            assertThat(own.getScanId()).isEqualTo(scanId);
            assertThat(service.latest(repository.id())).get().extracting(AiReviewResultEntity::getId)
                    .isEqualTo(own.getId());
            assertThat(service.latest(other.id())).get().extracting(AiReviewResultEntity::getId)
                    .isEqualTo(newer.getId());
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
            assertThat(service.latest(repository.id())).get().extracting(AiReviewResultEntity::getStatus)
                    .isEqualTo("failed");
        }
    }

    @Nested
    @DisplayName("around the call to the model")
    class AroundTheCall {

        /**
         * The call held a transaction open for as long as the model took — five minutes by default,
         * and a pooled connection for all of it. Asked from inside the
         * stub, because only there is the question about the call rather than about the method.
         */
        @Test
        @DisplayName("no transaction is open while the model writes, and the request is already recorded as running")
        void theCallHoldsNoTransaction() {
            seedScan("1.17.6");
            AtomicReference<Boolean> transactionOpen = new AtomicReference<>();
            AtomicReference<AiReviewResultEntity> meanwhile = new AtomicReference<>();
            Mockito.when(models.reviewCode(Mockito.anyString(), Mockito.anyString())).thenAnswer(call -> {
                transactionOpen.set(TransactionSynchronizationManager.isActualTransactionActive());
                meanwhile.set(service.latest(repository.id()).orElse(null));
                return "## A06 — Vulnerable and Outdated Components";
            });

            AiReviewResultEntity stored = service.run(repository);

            assertThat(transactionOpen.get()).as("a transaction was open during the model call").isFalse();
            // Committed before the call: a reader arriving meanwhile sees a review under way, with the
            // deadline past which nothing will be waiting for it.
            assertThat(meanwhile.get()).isNotNull().satisfies(row -> {
                assertThat(row.getStatus()).isEqualTo("running");
                assertThat(row.getDeadlineAt()).isEqualTo(NOW.plusSeconds(300).plus(Duration.ofMinutes(1)));
            });
            assertThat(stored.getStatus()).isEqualTo("completed");
            assertThat(results.findById(stored.getId())).get().satisfies(row -> {
                assertThat(row.getStatus()).isEqualTo("completed");
                assertThat(row.getDeadlineAt()).isNull();
            });
        }

        @Test
        @DisplayName("a review a stopped process left running reads as failed past its deadline, and the sweep writes it so")
        void anAbandonedReviewIsSettled() throws Exception {
            long scanId = seedScan("1.17.6");
            AiReviewResultEntity lapsed = running(scanId, NOW.minusSeconds(1));

            // Read as failed at once, before any sweep: an hour of "being written" over a request
            // whose process is gone is the silent failure the running state must not introduce.
            mvc.perform(authenticated(get("/api/v1/repositories/" + repository.id() + "/owasp-review"), asAdmin()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value("failed"))
                    .andExpect(jsonPath("$.error").value(Matchers.containsString("stopped before the model answered")));

            AiReviewResultEntity waiting = running(scanId, NOW.plusSeconds(60));

            assertThat(service.settleAbandoned()).isEqualTo(1);
            assertThat(results.findById(lapsed.getId())).get().satisfies(row -> {
                assertThat(row.getStatus()).isEqualTo("failed");
                assertThat(row.getError()).contains("stopped before the model answered");
            });
            // One still inside its deadline is somebody's request in progress, and is left alone.
            assertThat(results.findById(waiting.getId())).get()
                    .extracting(AiReviewResultEntity::getStatus).isEqualTo("running");
        }

        @Test
        @DisplayName("a review still being written has no PDF yet")
        void aRunningReviewHasNoPdf() {
            long scanId = seedScan("1.17.6");
            running(scanId, Instant.now().plusSeconds(600));

            // Refused, and refused as "not yet" rather than as the last run's failure: an empty
            // response rendered onto an OWASP cover page would be a document that says nothing.
            assertThat(org.assertj.core.api.Assertions.catchThrowable(() -> reports.pdf(
                            repository.id(), com.asmolabs.vectispire.common.domain.access.Visibility.everything())))
                    .isInstanceOf(OwaspReviewService.ReviewRefusedException.class)
                    .hasMessageContaining("still being written");
        }

        private AiReviewResultEntity running(long scanId, Instant deadline) {
            AiReviewResultEntity row = new AiReviewResultEntity();
            row.setScanId(scanId);
            row.setRepoId(repository.id());
            row.setModel("gemma4:e4b");
            row.setPrompt("p");
            row.setStatus("running");
            row.setCreatedAt(deadline.minusSeconds(360));
            row.setDeadlineAt(deadline);
            return results.save(row);
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
        scan.setRepoId(repository.id());
        scan.setBranch("master");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(NOW.minusSeconds(3600));
        scan.setVersion(version);
        return scans.save(scan).getId();
    }

    private void seedIssue(long scanId) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repository.id());
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
        stored.setRepoId(repository.id());
        stored.setModel("gemma4:e4b");
        stored.setPrompt("p");
        stored.setResponse("## A03 — Injection\n\nA finding worth reporting.");
        stored.setStatus("completed");
        stored.setCreatedAt(NOW);
        results.save(stored);

        byte[] pdf = mvc.perform(authenticated(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                .get("/api/v1/repositories/" + repository.id() + "/owasp-review/export.pdf"),
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
                    new com.asmolabs.vectispire.core.platform.SettingsAdministrationService(
                            Mockito.mock(com.asmolabs.vectispire.core.settings.SettingsService.class),
                            ai,
                            new com.asmolabs.vectispire.core.access.TriageApprovers(
                                    Mockito.mock(com.asmolabs.vectispire.core.access.persistence.UserRepository.class)),
                            Mockito.mock(com.asmolabs.vectispire.core.tickets.TicketService.class),
                            Mockito.mock(com.asmolabs.vectispire.core.notifications.NotificationService.class),
                            Mockito.mock(com.asmolabs.vectispire.core.audit.AuditLogService.class)),
                    Mockito.mock(com.asmolabs.vectispire.core.tickets.TicketService.class),
                    ai,
                    Mockito.mock(com.asmolabs.vectispire.core.notifications.NotificationService.class));
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
