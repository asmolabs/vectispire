package com.asmolabs.vectispire.core.issues;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.Issues;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;

/**
 * Who takes the decision when a VEX document is imported.
 *
 * <p>The answer was "nobody": the dismissal was recorded as made by {@code upstream_vex (<author>)},
 * the author read from the uploaded document; four-eyes was skipped; no audit entry was written;
 * every target in the deployment was matched; and the platform governor could do it. One upload
 * marked a CVE not affected across the estate with no trace of who did it.
 */
@DisplayName("importing a VEX document")
class VexImportAuthorityTest extends VectispireContextTest {

    private static final String DOCUMENT = """
            {
              "@context": "https://openvex.dev/ns/v0.2.0",
              "@id": "https://example.invalid/vex/1",
              "author": "Vendor X",
              "version": 1,
              "statements": [
                {
                  "vulnerability": {"name": "CVE-2026-7777"},
                  "products": [{"@id": "pkg:maven/org.example/lib@1.0.0"}],
                  "status": "not_affected",
                  "justification": "vulnerable_code_not_in_execute_path"
                }
              ]
            }""";

    @Autowired
    private VexIngestorService ingestor;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private AuditLogRepository audit;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("the decision is the uploader's, the document's author stays in the comment, and one audit entry records it")
    void theUploaderDecides() {
        long issueId = issue(repository("a"));

        ingestor.ingestPayload(DOCUMENT, caller("carol", Role.CISO, Visibility.everything()));

        IssueEntity after = issues.findById(issueId).orElseThrow();
        assertThat(after.getTriageStatus()).isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
        // It said "upstream_vex (Vendor X)" — whatever the uploaded file claimed.
        assertThat(after.getTriagedBy()).isEqualTo("carol");
        assertThat(after.getTriageComment()).contains("Vendor X");

        List<AuditLogEntity> entries = audit.findAllByOrderByTimestampAscIdAsc();
        assertThat(entries).singleElement().satisfies(entry -> {
            assertThat(entry.getUserId()).isEqualTo("carol");
            assertThat(entry.getIpAddress()).isEqualTo("192.0.2.1");
            assertThat(entry.getDescription()).startsWith("VEX import: 1 issue(s) triaged not affected")
                    .contains("CVE-2026-7777");
        });
    }

    @Test
    @DisplayName("only the targets the uploader may see are touched")
    void boundedByVisibility() {
        long mine = repository("mine");
        long theirs = repository("theirs");
        long visible = issue(mine);
        long hidden = issue(theirs);

        ingestor.ingestPayload(DOCUMENT, caller("carol", Role.CISO,
                Visibility.only(List.of(new ScanTarget.Repository(mine)))));

        assertThat(issues.findById(visible).orElseThrow().getTriageStatus())
                .isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
        assertThat(issues.findById(hidden).orElseThrow().getTriageStatus())
                .isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
    }

    @Test
    @DisplayName("with four-eyes on, an uploader who may not approve leaves the dismissal pending")
    void fourEyesApplies() {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "true");
        long issueId = issue(repository("a"));

        ingestor.ingestPayload(DOCUMENT, caller("sam", Role.USER, Visibility.everything()));

        assertThat(issues.findById(issueId).orElseThrow().getTriageStatus())
                .isEqualTo(TriageStatus.PENDING_APPROVAL.wireName());
        assertThat(audit.findAllByOrderByTimestampAscIdAsc()).singleElement()
                .satisfies(entry -> assertThat(entry.getDescription()).contains("(pending approval)"));
    }

    @Test
    @DisplayName("the platform governor is refused, and nothing is written")
    void theGovernorIsRefused() {
        long issueId = issue(repository("a"));

        assertThatThrownBy(() -> ingestor.ingestPayload(DOCUMENT, caller("root", Role.SUPERUSER, Visibility.everything())))
                .isInstanceOf(AccessDeniedException.class);

        assertThat(issues.findById(issueId).orElseThrow().getTriageStatus())
                .isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
        assertThat(audit.findAllByOrderByTimestampAscIdAsc()).isEmpty();
    }

    private static IssueDecisionService.Caller caller(String username, Role role, Visibility visibility) {
        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setRole(role.name());
        return new IssueDecisionService.Caller(Optional.of(UserView.of(user)), visibility, "192.0.2.1", "test");
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + ".git");
        repository.setName(name);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long issue(long repoId) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-" + repoId);
        issue.setIdentifier("CVE-2026-7777");
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setIsKev(false);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }
}
