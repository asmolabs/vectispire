package com.asmolabs.vectispire.core.forges.internal;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence;
import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence.MergedChange;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPager;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The change-review readers (decision 0037, lot G3) against recorded answers, through the real door — {@link
 * OutboundJson}, the pager, the guard — with only the exchange recorded: the URLs asked, and what each answer made
 * of the evidence. The answers are GitLab's and GitHub's documented shapes; the Community Edition's are what it
 * answers where the paid tiers' routes do not exist (404 on {@code /projects/:id/approvals}) and where they do
 * ({@code approved_by} on a merge request's approvals).
 */
@DisplayName("the change-review readers")
class ReviewReadersTest {

    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final Instant SINCE = NOW.minus(Duration.ofDays(30));
    private static final String GITLAB = "https://gitlab.example.org/api/v4";
    private static final String PROJECT = GITLAB + "/projects/42";
    private static final String GITHUB = "https://api.github.com";
    private static final String REPO = GITHUB + "/repos/acme/api";

    private GitHubListerTest.Recorded forge;

    @BeforeEach
    void start() {
        forge = new GitHubListerTest.Recorded();
    }

    private OutboundPager pager(String origin, Map<String, String> credential) {
        OutboundUrlGuard guard = new OutboundUrlGuard(host -> List.of(new byte[] {(byte) 140, 82, 112, 6}));
        return new OutboundJson(forge, guard, new ObjectMapper()).pager(new OutboundPager.Settings(origin,
                OutboundPolicy.PUBLIC_ONLY, "forge", credential, Optional.empty(), NOW.plus(Duration.ofMinutes(2)),
                Duration.ofSeconds(60), OutboundJson.TIMEOUT, null), new GitHubListerTest.MovingClock(NOW),
                duration -> {});
    }

    private static PinnedHttpSender.Response json(String body, String... headers) {
        Map<String, List<String>> all = new HashMap<>();
        for (int i = 0; i < headers.length; i += 2) {
            all.put(headers[i].toLowerCase(java.util.Locale.ROOT), List.of(headers[i + 1]));
        }
        return new PinnedHttpSender.Response(200, body, all);
    }

    private static PinnedHttpSender.Response status(int status) {
        return new PinnedHttpSender.Response(status, "{\"message\":\"" + status + "\"}", Map.of());
    }

    private static String days(int before) {
        return NOW.minus(Duration.ofDays(before)).toString();
    }

    // ---------------------------------------------------------------- GitLab

    @Nested
    @DisplayName("GitLab")
    class GitLab {

        private final GitLabReviewReader reader = new GitLabReviewReader();

        private ReviewReader.Reading read(Optional<String> branch, int maxChanges) {
            return reader.read(pager(GITLAB, reader.credential("glpat-review")), GITLAB, "42", branch, SINCE, 30, // gitleaks:allow
                    maxChanges);
        }

        private static String mergeRequests() {
            return PROJECT + "/merge_requests?state=merged&target_branch=main&updated_after=" + SINCE
                    + "&order_by=updated_at&sort=desc&per_page=100";
        }

        private static String mergeRequest(int iid, int mergedDaysAgo, int author) {
            return "{\"iid\":" + iid + ",\"state\":\"merged\",\"merged_at\":\"" + days(mergedDaysAgo) + "\",\"updated_at\":\""
                    + days(mergedDaysAgo) + "\",\"author\":{\"id\":" + author + ",\"username\":\"u" + author + "\"}}";
        }

        /** The Community Edition's answer: approved_by, and none of the paid tiers' fields. */
        private static String approvals(int iid, int... approvers) {
            StringBuilder by = new StringBuilder();
            for (int approver : approvers) {
                by.append(by.isEmpty() ? "" : ",").append("{\"user\":{\"id\":").append(approver)
                        .append(",\"username\":\"u").append(approver).append("\"}}");
            }
            return "{\"id\":1,\"iid\":" + iid + ",\"project_id\":42,\"state\":\"merged\",\"approved\":"
                    + (approvers.length > 0) + ",\"user_has_approved\":false,\"user_can_approve\":false,"
                    + "\"approved_by\":[" + by + "]}";
        }

        @BeforeEach
        void aProject() {
            forge.on(PROJECT, json("{\"id\":42,\"path_with_namespace\":\"group/app\",\"default_branch\":\"main\"}"));
        }

        @Test
        @DisplayName("Community Edition: no approval settings (404), the history read, the author's own approval excluded")
        void communityEdition() {
            forge.on(PROJECT + "/approvals", status(404));
            forge.on(mergeRequests(), json("[" + mergeRequest(3, 1, 7) + "," + mergeRequest(2, 5, 7) + ","
                    + mergeRequest(1, 31, 7) + "]"));
            forge.on(PROJECT + "/merge_requests/3/approvals", json(approvals(3, 8, 9)));
            forge.on(PROJECT + "/merge_requests/2/approvals", json(approvals(2, 7)));

            ReviewReader.Reading reading = read(Optional.empty(), 500);

            assertThat(reading).isInstanceOfSatisfying(ReviewReader.Reading.Read.class, read -> {
                ChangeReviewEvidence evidence = read.evidence();
                assertThat(evidence.project()).isEqualTo("group/app");
                assertThat(evidence.branch()).as("the default branch GitLab names").isEqualTo("main");
                assertThat(evidence.settings()).isEmpty();
                assertThat(evidence.settingsUnread()).get().asString().contains("HTTP 404").contains("Community Edition");
                assertThat(evidence.history()).get().satisfies(history -> {
                    assertThat(history.complete()).isTrue();
                    assertThat(history.changes()).as("!1 merged before the window, though updated in it: left out")
                            .containsExactly(new MergedChange("!3", NOW.minus(Duration.ofDays(1)), 2, false),
                                    new MergedChange("!2", NOW.minus(Duration.ofDays(5)), 0, true));
                });
            });
            assertThat(forge.urls()).as("one listing, one approvals request per change in the window, no rule asked")
                    .containsExactly(PROJECT, PROJECT + "/approvals", mergeRequests(),
                            PROJECT + "/merge_requests/3/approvals", PROJECT + "/merge_requests/2/approvals");
            assertThat(forge.seen).allSatisfy(request -> assertThat(request.headers())
                    .containsEntry("PRIVATE-TOKEN", "glpat-review")); // gitleaks:allow
        }

        @Test
        @DisplayName("Premium: approval rules, author approval prevented and a branch nobody pushes to make the settings")
        void premium() {
            forge.on(PROJECT + "/approvals", json("{\"approvals_before_merge\":0,\"reset_approvals_on_push\":true,"
                    + "\"merge_requests_author_approval\":false,\"merge_requests_disable_committers_approval\":true}"));
            forge.on(PROJECT + "/protected_branches/main", json("{\"id\":1,\"name\":\"main\",\"push_access_levels\":"
                    + "[{\"id\":1,\"access_level\":0,\"access_level_description\":\"No one\",\"user_id\":null,"
                    + "\"group_id\":null,\"deploy_key_id\":null}],\"merge_access_levels\":[{\"access_level\":40}]}"));
            forge.on(PROJECT + "/approval_rules?per_page=100", json("[{\"id\":1,\"name\":\"All members\","
                    + "\"rule_type\":\"any_approver\",\"approvals_required\":1,\"protected_branches\":[],"
                    + "\"applies_to_all_protected_branches\":false},{\"id\":2,\"name\":\"Release\",\"rule_type\":\"regular\","
                    + "\"approvals_required\":3,\"protected_branches\":[{\"id\":9,\"name\":\"release/*\"}],"
                    + "\"applies_to_all_protected_branches\":false},{\"id\":3,\"name\":\"Security\",\"rule_type\":\"regular\","
                    + "\"approvals_required\":2,\"protected_branches\":[],\"applies_to_all_protected_branches\":true},"
                    + "{\"id\":4,\"name\":\"Owners\",\"rule_type\":\"code_owner\",\"approvals_required\":5}]"));
            forge.on(mergeRequests(), json("[]"));

            ReviewReader.Reading reading = read(Optional.empty(), 500);

            assertThat(reading).isInstanceOfSatisfying(ReviewReader.Reading.Read.class, read -> {
                assertThat(read.evidence().settings()).get().satisfies(settings -> {
                    assertThat(settings.requiredApprovals()).as("the protected-branches rule's 2; release/* and the "
                            + "code owners' bind other branches or other changes").isEqualTo(2);
                    assertThat(settings.authorApprovalPrevented()).isTrue();
                    assertThat(settings.directPushRefused()).isTrue();
                    assertThat(settings.proves(2)).isTrue();
                    assertThat(settings.described()).contains("require 2 approvals on main")
                            .contains("author approval prevented").contains("direct push refused");
                });
                assertThat(read.evidence().history()).get().satisfies(history -> assertThat(history.changes()).isEmpty());
            });
        }

        @Test
        @DisplayName("Premium settings that let the author approve, or a developer push, prove nothing alone")
        void weakPremium() {
            forge.on(PROJECT + "/approvals", json("{\"merge_requests_author_approval\":true}"));
            forge.on(PROJECT + "/protected_branches/main", json("{\"name\":\"main\",\"push_access_levels\":"
                    + "[{\"access_level\":30,\"user_id\":null,\"group_id\":null}]}"));
            forge.on(PROJECT + "/approval_rules?per_page=100", json("[{\"rule_type\":\"regular\",\"approvals_required\":1,"
                    + "\"protected_branches\":[]}]"));
            forge.on(mergeRequests(), json("[]"));

            ChangeReviewEvidence evidence = ((ReviewReader.Reading.Read) read(Optional.empty(), 500)).evidence();

            assertThat(evidence.settings()).get().satisfies(settings -> {
                assertThat(settings.authorApprovalPrevented()).isFalse();
                assertThat(settings.directPushRefused()).isFalse();
                assertThat(settings.proves(1)).isFalse();
            });
        }

        @Test
        @DisplayName("a token refused the merge requests: the history says so; a project not shown: the reading is unreadable")
        void refusals() {
            forge.on(PROJECT + "/approvals", status(404));
            forge.on(mergeRequests(), status(403));

            ChangeReviewEvidence evidence = ((ReviewReader.Reading.Read) read(Optional.empty(), 500)).evidence();
            assertThat(evidence.history()).isEmpty();
            assertThat(evidence.historyUnread()).get().asString().contains("HTTP 403").contains("read_api")
                    .contains("Reporter");

            forge = new GitHubListerTest.Recorded();
            forge.on(PROJECT, status(404));
            assertThat(read(Optional.empty(), 500)).isInstanceOfSatisfying(ReviewReader.Reading.Unreadable.class,
                    unreadable -> assertThat(unreadable.why()).contains("does not show project 42").contains("HTTP 404"));

            forge = new GitHubListerTest.Recorded();
            forge.on(PROJECT, status(401));
            assertThat(read(Optional.empty(), 500)).isInstanceOfSatisfying(ReviewReader.Reading.Unreadable.class,
                    unreadable -> assertThat(unreadable.why()).contains("HTTP 401"));
        }

        @Test
        @DisplayName("the rule's branch, path-encoded; more merged changes than the bound: the history says it is cut short")
        void branchAndBound() {
            String release = PROJECT + "/merge_requests?state=merged&target_branch=release%2F2026&updated_after=" + SINCE
                    + "&order_by=updated_at&sort=desc&per_page=100";
            forge.on(PROJECT + "/approvals", status(404));
            forge.on(release, json("[" + mergeRequest(3, 1, 7) + "," + mergeRequest(2, 2, 7) + "," + mergeRequest(1, 3, 7)
                    + "]", "X-Next-Page", "2"));
            forge.on(PROJECT + "/merge_requests/3/approvals", json(approvals(3, 8)));
            forge.on(PROJECT + "/merge_requests/2/approvals", json(approvals(2, 8)));

            ChangeReviewEvidence evidence = ((ReviewReader.Reading.Read) read(Optional.of("release/2026"), 2)).evidence();

            assertThat(evidence.branch()).isEqualTo("release/2026");
            assertThat(evidence.history()).get().satisfies(history -> {
                assertThat(history.complete()).isFalse();
                assertThat(history.changes()).hasSize(2);
            });
            assertThat(forge.urls()).as("no second page and no third approvals once the bound is reached")
                    .doesNotContain(PROJECT + "/merge_requests/1/approvals").noneMatch(url -> url.contains("page=2"));
        }
    }

    // ---------------------------------------------------------------- GitHub

    @Nested
    @DisplayName("GitHub")
    class GitHub {

        private final GitHubReviewReader reader = new GitHubReviewReader();

        private ReviewReader.Reading read() {
            return reader.read(pager(GITHUB, reader.credential("github_pat_review")), GITHUB, "101", Optional.empty(), // gitleaks:allow
                    SINCE, 30, 500);
        }

        private static String pulls() {
            return REPO + "/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100";
        }

        private static String pull(int number, Integer mergedDaysAgo, int updatedDaysAgo, int author) {
            return "{\"number\":" + number + ",\"user\":{\"id\":" + author + "},\"updated_at\":\"" + days(updatedDaysAgo)
                    + "\",\"merged_at\":" + (mergedDaysAgo == null ? "null" : "\"" + days(mergedDaysAgo) + "\"") + "}";
        }

        private static String review(int user, String state) {
            return "{\"user\":{\"id\":" + user + "},\"state\":\"" + state + "\"}";
        }

        @BeforeEach
        void aRepository() {
            forge.on(GITHUB + "/repositories/101", json("{\"id\":101,\"full_name\":\"acme/api\",\"default_branch\":\"main\"}"));
        }

        @Test
        @DisplayName("rulesets requiring a review prove it; a protection exempting administrators does not alone")
        void settings() {
            forge.on(REPO + "/rules/branches/main?per_page=100", json("[{\"type\":\"deletion\"},{\"type\":\"pull_request\","
                    + "\"parameters\":{\"required_approving_review_count\":1,\"dismiss_stale_reviews_on_push\":true}}]"));
            forge.on(REPO + "/branches/main/protection", json("{\"required_pull_request_reviews\":"
                    + "{\"required_approving_review_count\":2},\"enforce_admins\":{\"enabled\":false}}"));
            forge.on(pulls(), json("[]"));

            ChangeReviewEvidence evidence = ((ReviewReader.Reading.Read) read()).evidence();

            assertThat(evidence.settings()).get().satisfies(settings -> {
                assertThat(settings.requiredApprovals()).as("the ruleset's 1; the protection's 2 binds no administrator")
                        .isEqualTo(1);
                assertThat(settings.proves(1)).isTrue();
                assertThat(settings.proves(2)).isFalse();
                assertThat(settings.described()).contains("rulesets require 1 approval")
                        .contains("administrators exempt").contains("author approval prevented by GitHub");
            });
            assertThat(forge.seen).allSatisfy(request -> assertThat(request.headers())
                    .containsEntry("X-GitHub-Api-Version", "2022-11-28"));
        }

        @Test
        @DisplayName("the history: merged pull requests in the window, a reviewer's latest decision, the author excluded")
        void history() {
            forge.on(REPO + "/rules/branches/main?per_page=100", json("[]"));
            forge.on(REPO + "/branches/main/protection", status(404));
            forge.on(pulls(), json("[" + pull(12, 1, 1, 7) + "," + pull(11, null, 2, 7) + "," + pull(10, 3, 3, 7) + ","
                    + pull(9, 4, 4, 7) + "," + pull(8, 60, 45, 7) + "," + pull(7, 2, 2, 7) + "]"));
            forge.on(REPO + "/pulls/12/reviews?per_page=100", json("[" + review(8, "COMMENTED") + "," + review(8, "APPROVED")
                    + "," + review(9, "APPROVED") + "]"));
            forge.on(REPO + "/pulls/10/reviews?per_page=100", json("[" + review(8, "APPROVED") + ","
                    + review(8, "CHANGES_REQUESTED") + "]"));
            forge.on(REPO + "/pulls/9/reviews?per_page=100", json("[" + review(7, "APPROVED") + "]"));

            ChangeReviewEvidence evidence = ((ReviewReader.Reading.Read) read()).evidence();

            assertThat(evidence.settings()).get().satisfies(settings -> assertThat(settings.proves(1)).isFalse());
            assertThat(evidence.history()).get().satisfies(history -> assertThat(history.changes()).containsExactly(
                    new MergedChange("#12", NOW.minus(Duration.ofDays(1)), 2, false),
                    new MergedChange("#10", NOW.minus(Duration.ofDays(3)), 0, false),
                    new MergedChange("#9", NOW.minus(Duration.ofDays(4)), 0, true)));
            assertThat(forge.urls()).as("#11 closed unmerged; #8 updated before the window ends the listing, #7 after it "
                    + "is never asked").doesNotContain(REPO + "/pulls/11/reviews?per_page=100",
                            REPO + "/pulls/7/reviews?per_page=100");
        }

        @Test
        @DisplayName("a fine-grained token without Pull requests: read is refused the pull requests, and the evidence says which permission")
        void withoutPullRequests() {
            forge.on(REPO + "/rules/branches/main?per_page=100", json("[]"));
            forge.on(REPO + "/branches/main/protection", status(403));
            forge.on(pulls(), status(403));

            ChangeReviewEvidence evidence = ((ReviewReader.Reading.Read) read()).evidence();

            assertThat(evidence.history()).isEmpty();
            assertThat(evidence.historyUnread()).get().asString().contains("Pull requests: read");
            assertThat(evidence.settings()).get().satisfies(settings -> assertThat(settings.described())
                    .contains("Administration: read"));
        }
    }
}
