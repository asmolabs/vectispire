package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * The OWASP review's refusals are 409s that say why, through the routes.
 *
 * <p>Its javadoc promised 409 from the start; no handler mapped the exception, which lives in {@code
 * compliance.internal} where the handler cannot name it, so a review switched off, a repository never
 * scanned and a PDF of a failed run each answered 500. The service's own tests saw the exception and
 * passed — they called the service, and the status is the route's.
 */
@DisplayName("the OWASP review's refusals")
class OwaspReviewRefusalRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private AiReviewResultRepository results;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("a review while model review is switched off is a 409 that says where to turn it on")
    void switchedOff() throws Exception {
        MvcResult result = mvc.perform(authenticated(post(route(repository())), asAdmin())).andReturn();

        assertConflict(result, "Model review is switched off.");
    }

    @Test
    @DisplayName("a review of a repository nothing scanned is a 409, not a report over an empty backlog")
    void neverScanned() throws Exception {
        settings.set(Setting.AI_REVIEW_ENABLED, "true");

        MvcResult result = mvc.perform(authenticated(post(route(repository())), asAdmin())).andReturn();

        assertConflict(result, "This repository has never been scanned.");
    }

    @Test
    @DisplayName("the PDF of a run that produced no report is a 409, even to a client that asked for a PDF")
    void failedRunHasNoPdf() throws Exception {
        long repository = repository();
        AiReviewResultEntity failed = new AiReviewResultEntity();
        failed.setScanId(scan(repository));
        failed.setModel("gemma4:12b-it-qat");
        failed.setPrompt("-");
        failed.setStatus("failed");
        failed.setError("The model could not be reached.");
        failed.setCreatedAt(Instant.now());
        results.save(failed);

        MvcResult result = mvc.perform(authenticated(get(route(repository) + "/export.pdf"), asAdmin())
                        .accept(MediaType.APPLICATION_PDF))
                .andReturn();

        assertConflict(result, "The last run did not produce a report");
    }

    private void assertConflict(MvcResult result, String detail) throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(409);
        assertThat(result.getResponse().getContentType()).startsWith(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        assertThat(detailOf(result)).startsWith(detail);
    }

    private static String route(long repository) {
        return "/api/v1/repositories/" + repository + "/owasp-review";
    }

    private long repository() {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("https://example.invalid/owasp-refusals.git");
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private long scan(long repository) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repository);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(Instant.now().minusSeconds(3600));
        return scans.save(scan).getId();
    }
}
