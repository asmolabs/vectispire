package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.threatintel.EpssFile;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.EpssScoreRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelRepository;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncEntity;
import com.asmolabs.vectispire.core.threatintel.persistence.ThreatIntelSyncRepository;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the EPSS and CISA KEV prioritization routes")
class EpssRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositoriesRepo;

    @Autowired
    private IssueRepository issuesRepo;

    @Autowired
    private ThreatIntelRepository intel;

    @Autowired
    private EpssScoreRepository scores;

    @Autowired
    private ThreatIntelSyncRepository syncs;

    /**
     * The field is called {@code topPriorities}, and it used to return the whole estate.
     *
     * <p>Sixty open issues, deliberately more than the fifty the ranking returns, and the check is
     * two-sided: the list is cut <b>and</b> the figures beside it are not. A cut that also shrank
     * {@code totalVulnerabilities} would under-report the backlog on the one screen an operator
     * reads it from, which is worse than the unbounded list it replaces.
     */
    @Test
    @DisplayName("the ranking is a top, and cutting it does not shrink the counts beside it")
    void theRankingIsCutButTheCountsAreNot() throws Exception {
        String token = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/wide-estate");
        repo.setUrl("https://example.invalid/wide-estate.git");
        repo.setBranch("main");
        repo = repositoriesRepo.save(repo);

        for (int index = 0; index < 60; index++) {
            IssueEntity issue = new IssueEntity();
            issue.setRepoId(repo.getId());
            issue.setType("sca");
            issue.setIdentifier("CVE-2030-" + index);
            issue.setSeverity("HIGH");
            issue.setState("open");
            issue.setTriageStatus("untriaged");
            issue.setFingerprint("fp-wide-" + index);
            issue.setFirstSeenAt(Instant.now());
            issue.setLastSeenAt(Instant.now());
            issuesRepo.save(issue);
        }

        mvc.perform(authenticated(get("/api/v1/epss/priorities"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.topPriorities.length()").value(50))
                .andExpect(jsonPath("$.totalVulnerabilities").value(60));
    }

    @Test
    @DisplayName("a CVE the feed does not know is reported without an EPSS, and left out of the mean")
    void anUnknownScoreIsNotInvented() throws Exception {
        // It was reported as 0.01, with a percentile of 0.011 made up from it, and averaged in.
        String token = asAdmin();
        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/unknown-intel");
        repo.setUrl("https://example.invalid/unknown-intel.git");
        repo.setBranch("main");
        repo = repositoriesRepo.save(repo);
        for (String[] row : new String[][] {{"CVE-2031-0001", "0.40"}, {"CVE-2031-0002", null}}) {
            IssueEntity issue = new IssueEntity();
            issue.setRepoId(repo.getId());
            issue.setType("sca");
            issue.setIdentifier(row[0]);
            issue.setSeverity("HIGH");
            issue.setState("open");
            issue.setTriageStatus("untriaged");
            issue.setFingerprint("fp-" + row[0]);
            issue.setFirstSeenAt(Instant.now());
            issue.setLastSeenAt(Instant.now());
            issue.setEpssScore(row[1] == null ? null : Double.valueOf(row[1]));
            issuesRepo.save(issue);
        }

        mvc.perform(authenticated(get("/api/v1/epss/priorities"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.averageFleetEpss").value(0.4))
                .andExpect(jsonPath("$.topPriorities[?(@.identifier == 'CVE-2031-0002')].epssScore").value(org.hamcrest.Matchers.contains((Object) null)))
                .andExpect(jsonPath("$.topPriorities[?(@.identifier == 'CVE-2031-0002')].epssPercentile").value(org.hamcrest.Matchers.contains((Object) null)));
    }

    @Test
    @DisplayName("retrieves EPSS fleet summary and priority rankings")
    void retrievesPriorities() throws Exception {
        String token = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/auth-service");
        repo.setUrl("https://github.com/corp/auth-service.git");
        repo.setBranch("main");
        repo = repositoriesRepo.save(repo);

        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repo.getId());
        issue.setType("sca");
        issue.setIdentifier("CVE-2021-44228");
        issue.setDescription("Remote Code Execution in Apache Log4j");
        issue.setSeverity("CRITICAL");
        issue.setCvssScore(10.0);
        issue.setKev(true);
        issue.setEpssScore(0.975);
        issue.setState("open");
        issue.setTriageStatus("untriaged");
        issue.setFingerprint("fp-log4shell-test");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issuesRepo.save(issue);

        mvc.perform(authenticated(get("/api/v1/epss/priorities"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalVulnerabilities").isNumber())
                .andExpect(jsonPath("$.activeKevCount").isNumber())
                .andExpect(jsonPath("$.topPriorities[0].identifier").value("CVE-2021-44228"))
                .andExpect(jsonPath("$.topPriorities[0].priorityTier").value("CRITICAL_ARMED"))
                .andExpect(jsonPath("$.topPriorities[0].priorityScore").isNumber())
                // Nothing computes reachability, so the ranking neither weighs nor publishes it.
                .andExpect(jsonPath("$.reachableEpssCount").doesNotExist())
                .andExpect(jsonPath("$.topPriorities[0].reachability").doesNotExist());

        // What the feed table holds, and nothing else: the lookup used to fall back on ten records
        // typed into the service, so this answered on an installation that had read no catalogue.
        mvc.perform(authenticated(get("/api/v1/epss/cve/CVE-2021-44228"), token))
                .andExpect(status().isNotFound());
        ThreatIntelEntity listed = new ThreatIntelEntity();
        listed.setCveId("CVE-2021-44228");
        listed.setKev(true);
        listed.setDateAdded(Instant.parse("2021-12-10T00:00:00Z"));
        intel.save(listed);
        // The score from the stored EPSS file — the generation the sync row names — and the flag from
        // the catalogue: one record from the two feeds.
        long generation = 42;
        scores.insertAll(generation, List.of(new EpssFile.Score("CVE-2021-44228", 0.975, 0.9998)));
        Instant now = Instant.now();
        syncs.save(new ThreatIntelSyncEntity());
        syncs.claimEpss(ThreatIntelSyncEntity.SINGLETON_ID, now, now.plusSeconds(60), generation);
        syncs.applyEpss(ThreatIntelSyncEntity.SINGLETON_ID, generation, now, "v2025.03.14", now, 1);
        mvc.perform(authenticated(get("/api/v1/epss/cve/cve-2021-44228"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveId").value("CVE-2021-44228"))
                .andExpect(jsonPath("$.isKev").value(true))
                .andExpect(jsonPath("$.epssScore").value(0.975))
                .andExpect(jsonPath("$.epssPercentile").value(0.9998));

        // No test reaches CISA (the suite's catalogue address cannot resolve): the sync answers, and
        // says it failed and why, rather than claiming a catalogue it never read.
        mvc.perform(authenticated(post("/api/v1/epss/sync"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("FAILED"))
                .andExpect(jsonPath("$.lastError").isString());
    }
}
