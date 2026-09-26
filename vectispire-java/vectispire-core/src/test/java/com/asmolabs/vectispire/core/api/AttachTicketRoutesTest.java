package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.audit.persistence.AuditLog;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Attaching an existing ticket to a finding.
 *
 * <h2>Why this endpoint exists</h2>
 *
 * <p><b>The sweep opened tickets, and nobody else could attach one.</b> It deals only with
 * findings that breach the gate, using the globally configured tracker. A team tracking a finding
 * in {@code SEC-1234} had no way of saying so — and the closing webhook, which looks the finding
 * up <em>by its reference</em>, could therefore not recognise it.
 *
 * <p>The cases are about the field aimed at as much as about the write: {@code ticketRef} is what
 * the list shows, what the webhook looks up and what the sweep reads. A second table exists for
 * this, with an endpoint of its own, and nothing reads it — writing there would have shipped an
 * attachment that synchronisation ignores.
 */
@DisplayName("le rattachement d'un ticket")
class AttachTicketRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private AuditLog auditLogs;

    @Test
    @DisplayName("writes the reference the webhook will look up, and returns it")
    void attachesTheReferenceTheWebhookLooksFor() throws Exception {
        long id = seedIssue();

        mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "SEC-1234", "url", "https://tracker.invalid/SEC-1234"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticketRef").value("SEC-1234"));

        // The field, not the second table: it is the one `findByTicketRefOrIid` searches.
        assertThat(issues.findByTicketRefOrIid("SEC-1234"))
                .as("the tracker's webhook must be able to find this finding by its reference")
                .isPresent()
                .get()
                .satisfies(issue -> assertThat(issue.getId()).isEqualTo(id));
    }

    @Test
    @DisplayName("accepts a reference with no URL, because an internal tracker may not have one")
    void theUrlIsOptional() throws Exception {
        long id = seedIssue();

        mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "#87"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticketRef").value("#87"));

        // Requiring a URL would make the reference alone a rejected entry, although the list
        // already knows how to show it without a link.
        assertThat(issues.findById(id).orElseThrow().getTicketUrl()).isNull();
    }

    @Test
    @DisplayName("refuses an empty reference rather than erasing the one that exists")
    void anEmptyReferenceIsRefused() throws Exception {
        long id = seedIssue();
        issues.attachTicket(id, "SEC-1", "https://tracker.invalid/SEC-1");

        mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "   "))))
                .andExpect(status().isBadRequest());

        // A field emptied by mistake would make the finding invisible to the webhook *and* reopen
        // the door to a second ticket from the sweep, with nothing saying so.
        assertThat(issues.findById(id).orElseThrow().getTicketRef()).isEqualTo("SEC-1");
    }

    @Test
    @DisplayName("lets a human correct their typo, and writes it to the log")
    void aHumanMayCorrectTheReference() throws Exception {
        long id = seedIssue();
        issues.attachTicket(id, "SEC-1233", null);

        mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "SEC-1234"))))
                .andExpect(status().isOk());

        assertThat(issues.findById(id).orElseThrow().getTicketRef()).isEqualTo("SEC-1234");

        // Replacing the reference changes who can close this finding from outside: that is a
        // decision, and it is recorded as one.
        assertThat(auditLogs.findAll())
                .anySatisfy(entry -> assertThat(entry.getDescription())
                        .contains("changed from SEC-1233 to SEC-1234"));
    }

    @Test
    @DisplayName("refuse un compte qui ne peut rien changer")
    void anAuditorMayNotAttach() throws Exception {
        long id = seedIssue();

        mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAuditor())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "SEC-1234"))))
                .andExpect(status().isForbidden());

        assertThat(issues.findById(id).orElseThrow().getTicketRef()).isNull();
    }

    @Test
    @DisplayName("answers 404 for a finding that does not exist")
    void anAbsentIssueIsNotFound() throws Exception {
        mvc.perform(authenticated(put("/api/v1/issues/999999/ticket"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "SEC-1234"))))
                .andExpect(status().isNotFound());
    }

    @Autowired
    private com.asmolabs.vectispire.core.settings.SettingsService settings;

    @Test
    @DisplayName("with a tracker configured, only a reference it issues, in its project, is accepted")
    void theReferenceMustBeTheTrackers() throws Exception {
        settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_PROVIDER, "jira");
        settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_PROJECT, "SEC");
        try {
            long id = seedIssue();
            for (String hostile : new String[] {"../../../../api/now/table/sys_user?", "HR-7"}) {
                mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAdmin())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of("reference", hostile))))
                        .andExpect(status().isBadRequest());
            }
            assertThat(issues.findById(id).orElseThrow().getTicketRef()).isNull();

            mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(Map.of("reference", "SEC-42"))))
                    .andExpect(status().isOk());
            assertThat(issues.findById(id).orElseThrow().getTicketAttachedBy()).isNotBlank();
        } finally {
            settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_PROVIDER, "none");
            settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_PROJECT, "");
        }
    }

    @Test
    @DisplayName("a ticket a person attached is not closed by the sweep; one Vectispire opened is")
    void onlyTicketsVectispireOpenedAreClosed() {
        // Attaching somebody else's ticket to a finding one can resolve made the integration close
        // it with its own token.
        long attached = seedIssue();
        issues.attachTicketBy(attached, "SEC-500", null, "developer");
        long opened = seedIssue();
        issues.attachTicket(opened, "SEC-501", null);
        for (long id : new long[] {attached, opened}) {
            IssueEntity issue = issues.findById(id).orElseThrow();
            issue.setState(IssueState.RESOLVED.wireName());
            issues.save(issue);
        }

        assertThat(issues.findResolvedWithOpenTicket(org.springframework.data.domain.Limit.of(100)))
                .extracting(IssueEntity::getId)
                .contains(opened)
                .doesNotContain(attached);
    }

    private long seedIssue() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/tickets.git");
        repository.setBranch("main");
        long repoId = repositories.save(repository).getId();

        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-ticket-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-4242");
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.parse("2026-09-01T10:00:00Z"));
        issue.setLastSeenAt(Instant.parse("2026-09-01T10:00:00Z"));
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }
}
