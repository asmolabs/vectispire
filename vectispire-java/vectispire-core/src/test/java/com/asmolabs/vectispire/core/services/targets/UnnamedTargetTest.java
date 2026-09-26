package com.asmolabs.vectispire.core.services.targets;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.posture.SecurityDebtService;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Clock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * A repository whose operator never chose a name.
 *
 * <h2>The ordinary case, and it answered 500</h2>
 *
 * <p><b>The name is optional</b> — a clone URL already carries a perfectly good one, so a
 * repository registered without one is not an edge case but the default. {@code SecurityDebtService}
 * read {@code getName()} straight off the entity into a {@code Collectors.toMap}, which refuses a
 * null value, and the remediation plan threw.
 *
 * <p>What made it hard to see from the outside: the <em>global</em> plan answered normally. Only
 * narrowing to the unnamed repository failed — the one gesture an operator makes when the global
 * list does not mention their repository, which is exactly what brought this to light.
 *
 * <p>The second assertion is the reason the fix is a delegation rather than a null check. Had the
 * null been defended against locally, this screen would have gone on calling a repository
 * something no other screen calls it: {@code TargetNaming} is the single rule, and every other
 * view already goes through it.
 */
@DisplayName("a target with no operator-chosen name")
class UnnamedTargetTest extends VectispireContextTest {

    @Autowired
    private SecurityDebtService debt;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("does not make the remediation plan fail")
    void unnamedRepositoryDoesNotBreakThePlan() {
        long repoId = unnamed("ssh://git@example.invalid:2222/common/common-libs.git");
        vulnerability(repoId, "CVE-2026-0001", "log4j-core", "2.14.1", "2.17.1");

        assertThat(debt.highImpactFixes(repoId, null, 10, Visibility.everything()))
                .as("the global plan answered; it threw once restricted to this repository, which "
                        + "is exactly the move one makes when the global list does not mention it")
                .isNotNull();
    }

    @Test
    @DisplayName("is named the way every other screen names it")
    void isNamedLikeEverywhereElse() {
        String url = "ssh://git@example.invalid:2222/common/common-libs.git";
        long repoId = unnamed(url);
        vulnerability(repoId, "CVE-2026-0002", "jackson-databind", "2.9.0", "2.15.0");

        // A local null guard would have been enough to stop the throw — and would have left this
        // screen calling the repository differently from every other.
        assertThat(debt.highImpactFixes(repoId, null, 10, Visibility.everything()))
                .allSatisfy(fix -> assertThat(fix.affectedTargetNames())
                        .allSatisfy(name -> assertThat(name).isEqualTo("common/common-libs")));
    }

    private long unnamed(String url) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setBranch("main");
        // No name: the column is optional, and this is the default case.
        return repositories.save(entity).getId();
    }

    private void vulnerability(long repoId, String cve, String pkg, String version, String fix) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-" + cve);
        issue.setIdentifier(cve);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setSeverity(Severity.CRITICAL.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setPackageName(pkg);
        issue.setPackageVersion(version);
        issue.setFixVersions(fix);
        issue.setFixState("fixed");
        issue.setPurl("pkg:maven/org.example/" + pkg + "@" + version);
        issue.setIsKev(false);
        issue.setFirstSeenAt(clock.instant());
        issue.setLastSeenAt(clock.instant());
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
