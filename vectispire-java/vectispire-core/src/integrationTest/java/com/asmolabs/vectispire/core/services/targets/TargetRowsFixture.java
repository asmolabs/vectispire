package com.asmolabs.vectispire.core.services.targets;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.targets.TargetDeleted;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.persistence.ApiContractEntity;
import com.asmolabs.vectispire.core.persistence.ApiEndpointEntity;
import com.asmolabs.vectispire.core.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.GatePolicyEntity;
import com.asmolabs.vectispire.core.persistence.GateVerdictEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.persistence.TeamEntity;
import com.asmolabs.vectispire.core.persistence.TeamTargetEntity;
import com.asmolabs.vectispire.core.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.persistence.UserTargetEntity;
import com.asmolabs.vectispire.core.repositories.AiReviewResults;
import com.asmolabs.vectispire.core.repositories.ApiContracts;
import com.asmolabs.vectispire.core.repositories.ApiEndpoints;
import com.asmolabs.vectispire.core.repositories.Components;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GatePolicies;
import com.asmolabs.vectispire.core.repositories.GateVerdicts;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.repositories.TeamTargets;
import com.asmolabs.vectispire.core.repositories.Teams;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
import com.asmolabs.vectispire.core.repositories.UserTargets;
import com.asmolabs.vectispire.core.repositories.Users;
import com.asmolabs.vectispire.core.tickets.persistence.IssueTicketEntity;
import com.asmolabs.vectispire.core.tickets.persistence.IssueTickets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * A target carrying a row in every table that names it, directly or through its issues and scans.
 *
 * <p><b>Two copies, kept identical:</b> under {@code src/test} for the unit suite on SQLite, and under
 * {@code src/integrationTest} for the campaign on PostgreSQL, MySQL and the fixture. The campaign's
 * source set does not see the unit suite's classes, and widening its classpath to them would bring
 * the unit suite's configuration along. Change one, change the other.
 *
 * <p>Rows are written through the entities rather than as SQL, so the same code runs on the three
 * engines whatever each calls a timestamp or a boolean; they are counted as SQL, so a row the
 * persistence context still holds but the database no longer has cannot pass for present.
 */
final class TargetRowsFixture {

    private static final Instant AT = Instant.parse("2026-09-01T10:00:00Z");

    private final BeanFactory beans;
    private final JdbcTemplate jdbc;

    TargetRowsFixture(BeanFactory beans, JdbcTemplate jdbc) {
        this.beans = beans;
        this.jdbc = jdbc;
    }

    ScanTarget repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + ".git");
        repository.setName(name);
        repository.setBranch("main");
        return new ScanTarget.Repository(beans.getBean(GitRepositories.class).save(repository).getId());
    }

    ScanTarget container(String name) {
        ContainerEntity container = new ContainerEntity();
        container.setImageName("example/" + name);
        container.setTag("1.0");
        return new ScanTarget.Container(beans.getBean(Containers.class).save(container).getId());
    }

    /** One row per dependent table, all naming {@code target}. */
    void populate(ScanTarget target) {
        TargetDeleted named = new TargetDeleted(target);
        Long repoId = target instanceof ScanTarget.Repository r ? r.id() : null;
        Long containerId = target instanceof ScanTarget.Container c ? c.id() : null;
        String suffix = named.kind() + "-" + named.id() + "-" + UUID.randomUUID();

        UserEntity user = new UserEntity();
        user.setUsername("grantee-" + suffix);
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setCreatedAt(AT);
        user.setUpdatedAt(AT);
        long userId = beans.getBean(Users.class).save(user).getId();
        beans.getBean(UserTargets.class).save(new UserTargetEntity(userId, named.kind(), named.id()));

        TeamEntity team = new TeamEntity();
        team.setName("team-" + suffix);
        team.setCreatedAt(AT);
        long teamId = beans.getBean(Teams.class).save(team).getId();
        beans.getBean(TeamTargets.class).save(new TeamTargetEntity(teamId, named.kind(), named.id()));

        GatePolicyEntity policy = new GatePolicyEntity();
        policy.setTargetKind(named.kind());
        policy.setTargetId(named.id());
        policy.setVersion(1);
        policy.setIsActive(true);
        policy.setCreatedAt(AT);
        beans.getBean(GatePolicies.class).save(policy);

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setContainerId(containerId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(AT);
        long scanId = beans.getBean(Scans.class).save(scan).getId();

        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setContainerId(containerId);
        issue.setFingerprint(suffix.substring(0, Math.min(64, suffix.length())));
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2021-44228");
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(AT);
        issue.setLastSeenAt(AT);
        issue.setFirstSeenScanId(scanId);
        issue.setLastSeenScanId(scanId);
        issue.setTimesSeen(1);
        long issueId = beans.getBean(Issues.class).save(issue).getId();

        TriageEventEntity event = new TriageEventEntity();
        event.setIssueId(issueId);
        event.setScanId(scanId);
        event.setFromStatus(TriageStatus.UNDER_REVIEW.wireName());
        event.setToStatus(TriageStatus.UNDER_REVIEW.wireName());
        event.setOrigin("system");
        event.setOccurredAt(AT);
        beans.getBean(TriageEvents.class).save(event);

        IssueTicketEntity ticket = new IssueTicketEntity();
        ticket.setIssueId(issueId);
        ticket.setProvider("jira");
        ticket.setTicketKey("SEC-1");
        ticket.setTicketUrl("https://tracker.invalid/SEC-1");
        ticket.setStatus("open");
        ticket.setCreatedAt(AT);
        ticket.setUpdatedAt(AT);
        beans.getBean(IssueTickets.class).save(ticket);

        FindingEntity finding = new FindingEntity();
        finding.setScanId(scanId);
        finding.setIssueId(issueId);
        finding.setType(FindingType.VULNERABILITY.wireName());
        finding.setIdentifier("CVE-2021-44228");
        finding.setSeverity(Severity.HIGH.wireName());
        finding.setPackageName("log4j-core");
        finding.setSource("grype");
        finding.setCreatedAt(AT);
        beans.getBean(Findings.class).save(finding);

        ComponentEntity component = new ComponentEntity();
        component.setScanId(scanId);
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        beans.getBean(Components.class).save(component);

        AiReviewResultEntity review = new AiReviewResultEntity();
        review.setScanId(scanId);
        review.setModel("model");
        review.setPrompt("prompt");
        review.setStatus("completed");
        review.setCreatedAt(AT);
        beans.getBean(AiReviewResults.class).save(review);

        GateVerdictEntity verdict = new GateVerdictEntity();
        verdict.setId(UUID.randomUUID());
        verdict.setRepoId(repoId);
        verdict.setContainerId(containerId);
        verdict.setPassed(true);
        verdict.setPolicySource("default");
        verdict.setDecidedAt(AT);
        beans.getBean(GateVerdicts.class).save(verdict);

        if (repoId != null) {
            ApiEndpointEntity endpoint = new ApiEndpointEntity();
            endpoint.setScanId(scanId);
            endpoint.setRepositoryId(repoId);
            endpoint.setHttpMethod("GET");
            endpoint.setPath("/orders");
            endpoint.setAuthRequired(false);
            endpoint.setVisibility("PUBLIC");
            endpoint.setCreatedAt(AT);
            beans.getBean(ApiEndpoints.class).save(endpoint);

            ApiContractEntity contract = new ApiContractEntity();
            contract.setRepositoryId(repoId);
            contract.setScanId(scanId);
            contract.setContractPath("openapi.yaml");
            contract.setEndpointsCount(1);
            contract.setCreatedAt(AT);
            beans.getBean(ApiContracts.class).save(contract);
        }
    }

    /**
     * How many rows each dependent table holds for {@code target}, reached the way the schema reaches
     * them: by the target's column, or through its issues and scans.
     */
    Map<String, Integer> rowsNaming(ScanTarget target) {
        TargetDeleted named = new TargetDeleted(target);
        String column = target instanceof ScanTarget.Repository ? "repo_id" : "container_id";
        long id = named.id();
        String issues = "select i.id from t_issue i where i." + column + " = " + id;
        String scans = "select s.id from t_scan s where s." + column + " = " + id;
        // Children are also reached through the identifiers the fixture wrote, so a child whose
        // parent was deleted without it — the orphan this test exists to catch — still counts.
        Map<String, Integer> rows = new LinkedHashMap<>();
        rows.put("t_user_target", count("t_user_target where target_kind = ? and target_id = ?", named.kind(), id));
        rows.put("t_team_target", count("t_team_target where target_kind = ? and target_id = ?", named.kind(), id));
        rows.put("t_gate_policy", count("t_gate_policy where target_kind = ? and target_id = ?", named.kind(), id));
        rows.put("t_scan", count("t_scan where " + column + " = ?", id));
        rows.put("t_issue", count("t_issue where " + column + " = ?", id));
        rows.put("t_gate_verdict", count("t_gate_verdict where " + column + " = ?", id));
        rows.put("t_issue_triage_event", count("t_issue_triage_event where issue_id in (" + issues + ")"
                + " or issue_id not in (select id from t_issue)"));
        rows.put("t_issue_ticket", count("t_issue_ticket where issue_id in (" + issues + ")"
                + " or issue_id not in (select id from t_issue)"));
        rows.put("t_finding", count("t_finding where scan_id in (" + scans + ") or issue_id in (" + issues + ")"
                + " or scan_id not in (select id from t_scan)"));
        rows.put("t_component", count("t_component where scan_id in (" + scans + ")"
                + " or scan_id not in (select id from t_scan)"));
        rows.put("t_ai_review_result", count("t_ai_review_result where scan_id in (" + scans + ")"
                + " or scan_id not in (select id from t_scan)"));
        if (target instanceof ScanTarget.Repository) {
            rows.put("t_api_endpoint", count("t_api_endpoint where repository_id = ? or scan_id in (" + scans + ")"
                    + " or scan_id not in (select id from t_scan)", id));
            rows.put("t_api_contract", count("t_api_contract where repository_id = ? or scan_id in (" + scans + ")", id));
        }
        return rows;
    }

    private int count(String fromWhere, Object... arguments) {
        Integer count = jdbc.queryForObject("select count(*) from " + fromWhere, Integer.class, arguments);
        return count == null ? 0 : count;
    }
}
