package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.threatintel.EpssFile;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.EpssScoreRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
import java.time.Instant;
import java.util.List;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the AI Advisor and Explainer REST endpoints")
class AiAdvisorRoutesTest extends ApiTestBase {

    @Autowired
    private IssueRepository issuesRepo;

    @Autowired
    private ThreatIntelRepository intel;

    @Autowired
    private EpssScoreRepository scores;

    @Autowired
    private ThreatIntelSyncRepository syncs;

    @Test
    @DisplayName("GET /api/v1/ai-advisor/status returns model status")
    void getsStatus() throws Exception {
        mvc.perform(authenticated(get("/api/v1/ai-advisor/status"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").isBoolean())
                .andExpect(jsonPath("$.selectedModel").isString());
    }

    @Test
    @DisplayName("POST /api/v1/ai-advisor/explain/cve/{cveId} returns deterministic advice for CVE")
    void explainsCve() throws Exception {
        mvc.perform(authenticated(
                post("/api/v1/ai-advisor/explain/cve/CVE-2021-44228?packageName=log4j-core&currentVersion=2.14.1&fixVersion=2.17.1"),
                asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.identifier").value("CVE-2021-44228"))
                .andExpect(jsonPath("$.summaryExplanation").value(org.hamcrest.Matchers.containsString("log4j-core")))
                .andExpect(jsonPath("$.remediation.suggestedVersion").value("2.17.1"));
    }

    /**
     * The caller's word is not an analysis.
     *
     * <p>The route took a {@code reachability} parameter and made it the advice's exposure, so a
     * request saying REACHABLE had the product answer "a code finding mentions this component" —
     * about a CVE the estate may not even carry. The parameter is ignored now, not refused, so a
     * client still sending it keeps working.
     */
    @Test
    @DisplayName("a reachability passed by the caller is ignored: the exposure was not assessed")
    void theCallersReachabilityIsIgnored() throws Exception {
        mvc.perform(authenticated(
                post("/api/v1/ai-advisor/explain/cve/CVE-2021-44228?packageName=log4j-core&reachability=REACHABLE"),
                asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exposureAssessment").value(org.hamcrest.Matchers.startsWith("EXPOSURE NOT ASSESSED")))
                .andExpect(jsonPath("$.deterministic.exposure").doesNotExist());
    }

    /**
     * A CVE the estate does not carry, on an installation that has read neither feed.
     *
     * <p>This answer was made up: CVE-2021-44228 was "actively exploited" because its identifier was
     * one of two typed into the service, and every CVE came with an EPSS probability of 0.75 — shown
     * on screen as "EPSS probability: 75.0 %". Nothing had been read, and the answer says so.
     */
    @Test
    @DisplayName("a CVE nobody carries, with no feed read: exploitation and EPSS are unknown, not invented")
    void nothingReadIsUnknown() throws Exception {
        mvc.perform(authenticated(post("/api/v1/ai-advisor/explain/cve/CVE-2021-44228"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deterministic.kev").value("UNKNOWN"))
                .andExpect(jsonPath("$.deterministic.exploitProbability").value(Matchers.nullValue()))
                .andExpect(jsonPath("$.exploitMechanics").value(Matchers.containsString("EPSS probability: unknown")))
                .andExpect(jsonPath("$.exploitMechanics").value(Matchers.not(Matchers.containsString("75"))))
                // No component was named and none is recorded: nothing to upgrade, and no command
                // built around "the component".
                .andExpect(jsonPath("$.deterministic.packageName").value(Matchers.nullValue()))
                .andExpect(jsonPath("$.remediation.suggestedVersion").value(Matchers.nullValue()))
                .andExpect(jsonPath("$.remediation.cliCommand").value(""))
                .andExpect(jsonPath("$.vexSuggestion.status").value("under_investigation"));
    }

    /**
     * The same question once both feeds have been read: the answer is theirs.
     *
     * <p>CVE-2024-3094 was the second identifier typed in as exploited. Here the catalogue in use
     * does not list it, and it says so; CVE-2021-44228 is listed and scored, and those are the
     * figures shown.
     */
    @Test
    @DisplayName("a CVE nobody carries, with both feeds read: the catalogue's listing and the file's score")
    void theStoredFeedsAnswer() throws Exception {
        ThreatIntelEntity listed = new ThreatIntelEntity();
        listed.setCveId("CVE-2021-44228");
        listed.setKev(true);
        listed.setDateAdded(Instant.parse("2021-12-10T00:00:00Z"));
        intel.save(listed);
        long generation = 7;
        scores.insertAll(generation, List.of(new EpssFile.Score("CVE-2021-44228", 0.94358, 0.9995)));
        ThreatIntelSyncEntity sync = new ThreatIntelSyncEntity();
        sync.setId(ThreatIntelSyncEntity.SINGLETON_ID);
        sync.setLastSyncedAt(Instant.now());
        sync.setStatus("SYNCED");
        sync.setEpssGeneration(generation);
        sync.setEpssCount(1);
        syncs.save(sync);

        mvc.perform(authenticated(post("/api/v1/ai-advisor/explain/cve/cve-2021-44228"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deterministic.kev").value("LISTED"))
                .andExpect(jsonPath("$.deterministic.exploitProbability").value(0.94358))
                .andExpect(jsonPath("$.exploitMechanics").value(Matchers.containsString("EPSS probability: 94.358%")))
                .andExpect(jsonPath("$.vexSuggestion.status").value("affected"));

        mvc.perform(authenticated(post("/api/v1/ai-advisor/explain/cve/CVE-2024-3094"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deterministic.kev").value("NOT_LISTED"))
                .andExpect(jsonPath("$.deterministic.exploitProbability").value(Matchers.nullValue()))
                .andExpect(jsonPath("$.vexSuggestion.status").value("under_investigation"));
    }

    /**
     * An issue whose flag reads false before the catalogue was ever read.
     *
     * <p>{@code isKev} is false both for "not listed" and for "nobody looked"; the advice printed the
     * second as the first. The score the row carries is the EPSS file's word, and is kept.
     */
    @Test
    @DisplayName("an issue explained before any catalogue was read: its listing is unknown, its score its own")
    void anIssuesFalseFlagIsNotANotListed() throws Exception {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("test-fingerprint-ai-advisor-unread-catalogue");
        issue.setType("vulnerability");
        issue.setIdentifier("CVE-2022-42889");
        issue.setPackageName("commons-text");
        issue.setPackageVersion("1.9");
        issue.setState("open");
        issue.setSeverity("MEDIUM");
        issue.setTriageStatus("untriaged");
        issue.setKev(false);
        issue.setEpssScore(0.05);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issue = issuesRepo.save(issue);

        mvc.perform(authenticated(post("/api/v1/ai-advisor/explain/issue/" + issue.getId()), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deterministic.kev").value("UNKNOWN"))
                .andExpect(jsonPath("$.deterministic.exploitProbability").value(0.05))
                // No fix recorded on the row: none is claimed.
                .andExpect(jsonPath("$.deterministic.targetVersion").value(Matchers.nullValue()))
                .andExpect(jsonPath("$.remediation.fixAction").value("No fixed version is recorded for this vulnerability."));
    }

    @Test
    @DisplayName("POST /api/v1/ai-advisor/explain/issue/{issueId} explains existing issue entity")
    void explainsIssue() throws Exception {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("test-fingerprint-ai-advisor-001");
        issue.setType("vulnerability");
        issue.setIdentifier("CVE-2022-42889");
        issue.setPackageName("commons-text");
        issue.setPackageVersion("1.9");
        issue.setFixVersions("1.10.0");
        issue.setState("open");
        issue.setSeverity("MEDIUM");
        issue.setTriageStatus("under_review");
        issue.setKev(false);
        issue.setEpssScore(0.05);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issue = issuesRepo.save(issue);

        mvc.perform(authenticated(post("/api/v1/ai-advisor/explain/issue/" + issue.getId()), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.identifier").value("CVE-2022-42889"))
                // The suggestion arrives pre-filled in front of the person triaging: it cannot
                // offer an exemption deduced from a text correlation that stayed silent.
                .andExpect(jsonPath("$.vexSuggestion.status").value("under_investigation"))
                .andExpect(jsonPath("$.vexSuggestion.justification").doesNotExist());
    }
}
