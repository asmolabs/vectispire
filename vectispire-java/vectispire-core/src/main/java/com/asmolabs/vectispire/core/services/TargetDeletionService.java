package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.core.repositories.AiReviewResults;
import com.asmolabs.vectispire.core.repositories.Components;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GatePolicies;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.IssueTickets;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.repositories.TeamTargets;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
import com.asmolabs.vectispire.core.repositories.UserTargets;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Atomic target deletion and orphan cleanup across all databases (PostgreSQL, MySQL, MariaDB, SQLite).
 *
 * <p>Because MySQL/MariaDB and SQLite do not enable cascading deletion automatically on inline foreign
 * keys, deleting a container or repository must explicitly purge all attached issues, findings, components,
 * scans, triage events, tickets and gate policy overrides so that no stale findings or broken visibility
 * records remain in the system.
 */
@Service
public class TargetDeletionService {

    private static final Logger log = LoggerFactory.getLogger(TargetDeletionService.class);

    private final GitRepositories repositories;
    private final Containers containers;
    private final Issues issues;
    private final Scans scans;
    private final Findings findings;
    private final Components components;
    private final AiReviewResults aiReviewResults;
    private final TriageEvents triageEvents;
    private final IssueTickets issueTickets;
    private final GatePolicies gatePolicies;
    private final UserTargets userTargets;
    private final TeamTargets teamTargets;

    public TargetDeletionService(
            GitRepositories repositories,
            Containers containers,
            Issues issues,
            Scans scans,
            Findings findings,
            Components components,
            AiReviewResults aiReviewResults,
            TriageEvents triageEvents,
            IssueTickets issueTickets,
            GatePolicies gatePolicies,
            UserTargets userTargets,
            TeamTargets teamTargets) {
        this.repositories = repositories;
        this.containers = containers;
        this.issues = issues;
        this.scans = scans;
        this.findings = findings;
        this.components = components;
        this.aiReviewResults = aiReviewResults;
        this.triageEvents = triageEvents;
        this.issueTickets = issueTickets;
        this.gatePolicies = gatePolicies;
        this.userTargets = userTargets;
        this.teamTargets = teamTargets;
    }

    @Transactional
    public void deleteContainer(long containerId) {
        userTargets.deleteByTarget(TeamRules.KIND_CONTAINER, containerId);
        teamTargets.deleteByTarget(TeamRules.KIND_CONTAINER, containerId);
        gatePolicies.deleteByTarget(TeamRules.KIND_CONTAINER, containerId);

        List<Long> issueIds = issues.findIdsByContainerId(containerId);
        if (!issueIds.isEmpty()) {
            triageEvents.deleteByIssueIdIn(issueIds);
            issueTickets.deleteByIssueIdIn(issueIds);
            findings.deleteByIssueIdIn(issueIds);
            issues.deleteByIdIn(issueIds);
        }

        List<Long> scanIds = scans.findIdsByContainerId(containerId);
        if (!scanIds.isEmpty()) {
            findings.deleteByScanIdIn(scanIds);
            components.deleteByScanIdIn(scanIds);
            aiReviewResults.deleteByScanIdIn(scanIds);
            scans.deleteByIdIn(scanIds);
        }

        containers.deleteById(containerId);
        log.info("Container {} deleted along with {} issues and {} scans.", containerId, issueIds.size(), scanIds.size());
    }

    @Transactional
    public void deleteRepository(long repoId) {
        userTargets.deleteByTarget(TeamRules.KIND_REPOSITORY, repoId);
        teamTargets.deleteByTarget(TeamRules.KIND_REPOSITORY, repoId);
        gatePolicies.deleteByTarget(TeamRules.KIND_REPOSITORY, repoId);

        List<Long> issueIds = issues.findIdsByRepoId(repoId);
        if (!issueIds.isEmpty()) {
            triageEvents.deleteByIssueIdIn(issueIds);
            issueTickets.deleteByIssueIdIn(issueIds);
            findings.deleteByIssueIdIn(issueIds);
            issues.deleteByIdIn(issueIds);
        }

        List<Long> scanIds = scans.findIdsByRepoId(repoId);
        if (!scanIds.isEmpty()) {
            findings.deleteByScanIdIn(scanIds);
            components.deleteByScanIdIn(scanIds);
            aiReviewResults.deleteByScanIdIn(scanIds);
            scans.deleteByIdIn(scanIds);
        }

        repositories.deleteById(repoId);
        log.info("Repository {} deleted along with {} issues and {} scans.", repoId, issueIds.size(), scanIds.size());
    }

    /**
     * Purges any orphaned issues or scans whose parent repository/container no longer exists.
     * Triggered automatically on startup and available for periodic maintenance.
     */
    @Transactional
    @EventListener(ApplicationReadyEvent.class)
    public void purgeOrphanedTargetData() {
        List<Long> orphanedIssues = issues.findOrphanedIds();
        if (!orphanedIssues.isEmpty()) {
            triageEvents.deleteByIssueIdIn(orphanedIssues);
            issueTickets.deleteByIssueIdIn(orphanedIssues);
            findings.deleteByIssueIdIn(orphanedIssues);
            issues.deleteByIdIn(orphanedIssues);
            log.info("Cleaned up {} orphaned issues from deleted targets.", orphanedIssues.size());
        }

        List<Long> orphanedScans = scans.findOrphanedIds();
        if (!orphanedScans.isEmpty()) {
            findings.deleteByScanIdIn(orphanedScans);
            components.deleteByScanIdIn(orphanedScans);
            aiReviewResults.deleteByScanIdIn(orphanedScans);
            scans.deleteByIdIn(orphanedScans);
            log.info("Cleaned up {} orphaned scans from deleted targets.", orphanedScans.size());
        }
    }
}
