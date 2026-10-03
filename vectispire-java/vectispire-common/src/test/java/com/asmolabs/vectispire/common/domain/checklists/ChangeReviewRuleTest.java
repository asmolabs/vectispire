package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence.History;
import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence.MergedChange;
import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence.Settings;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Look;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ReviewFacts;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ReviewRead;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ReviewUnlinked;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ReviewUnreadable;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Source;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** The change-review rule (decision 0037, lot G3): its binding, and its evaluation over what the forges recorded. */
@DisplayName("a change-review rule")
class ChangeReviewRuleTest {

    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final Instant READ = NOW.minus(Duration.ofHours(3));

    private static ChecklistRule rule(String parameters) {
        return ChecklistRule.parse("{\"kind\":\"change_review\",\"maxAgeDays\":2," + parameters + "}");
    }

    private static final ChecklistRule EVERY_ONE = rule("\"minimumApprovals\":1,\"windowDays\":30,\"minimumRatio\":1");

    @Nested
    @DisplayName("bound")
    class Binding {

        @Test
        @DisplayName("writes one canonical form, the branch only when named, and reads it back to the same bytes")
        void canonical() {
            assertThat(EVERY_ONE.canonical()).isEqualTo("{\"kind\":\"change_review\",\"maxAgeDays\":2,"
                    + "\"minimumApprovals\":1,\"minimumRatio\":1,\"windowDays\":30}");
            ChecklistRule named = rule("\"minimumApprovals\":2,\"windowDays\":90,\"minimumRatio\":0.950,"
                    + "\"branch\":\" release/2026 \"");
            assertThat(named.canonical()).isEqualTo("{\"branch\":\"release/2026\",\"kind\":\"change_review\","
                    + "\"maxAgeDays\":2,\"minimumApprovals\":2,\"minimumRatio\":0.95,\"windowDays\":90}");
            assertThat(ChecklistRule.fromCanonical(named.canonical()).digest()).isEqualTo(named.digest());
        }

        @Test
        @DisplayName("states what no product default may decide: approvals, window and share are required")
        void nothingIsAssumed() {
            assertThatThrownBy(() -> rule("\"windowDays\":30,\"minimumRatio\":1"))
                    .isInstanceOf(InvalidInputException.class).hasMessageContaining("minimumApprovals");
            assertThatThrownBy(() -> rule("\"minimumApprovals\":1,\"minimumRatio\":1"))
                    .isInstanceOf(InvalidInputException.class).hasMessageContaining("windowDays");
            assertThatThrownBy(() -> rule("\"minimumApprovals\":1,\"windowDays\":30"))
                    .isInstanceOf(InvalidInputException.class).hasMessageContaining("minimumRatio");
        }

        @Test
        @DisplayName("refuses no approval, a window outside a day to a year and a day, a share of none, a branch Git refuses")
        void bounds() {
            assertThatThrownBy(() -> rule("\"minimumApprovals\":0,\"windowDays\":30,\"minimumRatio\":1"))
                    .isInstanceOf(InvalidInputException.class).hasMessageContaining("minimumApprovals");
            assertThatThrownBy(() -> rule("\"minimumApprovals\":11,\"windowDays\":30,\"minimumRatio\":1"))
                    .isInstanceOf(InvalidInputException.class);
            assertThatThrownBy(() -> rule("\"minimumApprovals\":1,\"windowDays\":0,\"minimumRatio\":1"))
                    .isInstanceOf(InvalidInputException.class).hasMessageContaining("windowDays");
            assertThatThrownBy(() -> rule("\"minimumApprovals\":1,\"windowDays\":367,\"minimumRatio\":1"))
                    .isInstanceOf(InvalidInputException.class);
            assertThatThrownBy(() -> rule("\"minimumApprovals\":1,\"windowDays\":30,\"minimumRatio\":0"))
                    .isInstanceOf(InvalidInputException.class).hasMessageContaining("minimumRatio");
            for (String branch : List.of("", "a b", "a..b", "a~1", "x:y", "x\\u0001")) {
                assertThatThrownBy(() -> rule("\"minimumApprovals\":1,\"windowDays\":30,\"minimumRatio\":1,\"branch\":\""
                        + branch + "\"")).as(branch).isInstanceOf(InvalidInputException.class).hasMessageContaining("branch");
            }
            assertThatThrownBy(() -> rule("\"minimumApprovals\":1,\"windowDays\":30,\"minimumRatio\":1,\"metric\":\"line\""))
                    .isInstanceOf(InvalidInputException.class).hasMessageContaining("takes no \"metric\"");
        }
    }

    @Nested
    @DisplayName("measured")
    class Evaluation {

        @Test
        @DisplayName("on the history: every merged change approved by a peer passes, and the evidence counts them")
        void historyPasses() {
            Measurement measured = evaluate(EVERY_ONE, Map.of(1L, read(history(true, change("!3", 2, 1, false),
                    change("!2", 5, 2, false), change("!1", 29, 1, false)))));

            assertThat(measured.outcome()).isEqualTo(MeasurementOutcome.PASS);
            assertThat(measured.summary()).contains("3 of 3 merged merge requests approved by a peer in 30 days");
            assertThat(measured.repositories()).singleElement().satisfies(evidence -> {
                assertThat(evidence.look()).map(Look::source).contains(Source.FORGE_REVIEW);
                assertThat(evidence.met()).contains(true);
            });
            assertThat(measured.asOf()).contains(READ);
        }

        @Test
        @DisplayName("an approval by the author alone is no review: the change fails, and the evidence names it")
        void selfApprovalIsNotAReview() {
            Measurement measured = evaluate(EVERY_ONE, Map.of(1L, read(history(true, change("!2", 2, 1, false),
                    change("!1", 3, 0, true)))));

            assertThat(measured.outcome()).isEqualTo(MeasurementOutcome.FAIL);
            assertThat(measured.summary()).contains("1 of 2 merged merge requests approved by a peer")
                    .contains("1 approved by their author too, not counted").contains("without: !1");
        }

        @Test
        @DisplayName("the share and the number of approvals are the rule's; changes before the window are not counted")
        void shareAndWindow() {
            List<MergedChange> changes = new ArrayList<>();
            for (int i = 1; i <= 9; i++) {
                changes.add(change("#" + i, i, 2, false));
            }
            changes.add(change("#10", 10, 1, false));
            changes.add(change("#11", 40, 0, false));
            Map<Long, ReviewFacts> recorded = Map.of(1L, read("github", 60, history(true, changes.toArray(MergedChange[]::new))));

            assertThat(evaluate(rule("\"minimumApprovals\":2,\"windowDays\":30,\"minimumRatio\":0.9"), recorded).outcome())
                    .as("9 of 10 with two approvals, #11 outside the window").isEqualTo(MeasurementOutcome.PASS);
            Measurement strict = evaluate(rule("\"minimumApprovals\":2,\"windowDays\":30,\"minimumRatio\":0.91"), recorded);
            assertThat(strict.outcome()).isEqualTo(MeasurementOutcome.FAIL);
            assertThat(strict.summary()).contains("9 of 10 merged pull requests approved by 2 peers").contains("without: #10");
            assertThat(evaluate(rule("\"minimumApprovals\":2,\"windowDays\":60,\"minimumRatio\":0.9"), recorded).outcome())
                    .as("#11 inside a sixty-day window").isEqualTo(MeasurementOutcome.FAIL);
            assertThat(evaluate(rule("\"minimumApprovals\":1,\"windowDays\":30,\"minimumRatio\":1"), recorded).outcome())
                    .isEqualTo(MeasurementOutcome.PASS);
        }

        @Test
        @DisplayName("on the settings: a configuration requiring the approvals passes without the history")
        void settingsProve() {
            ChangeReviewEvidence evidence = new ChangeReviewEvidence("gitlab", "group/app", "main", 30,
                    Optional.of(new Settings(2, true, true, "approval rules require 2 approvals, author approval prevented")),
                    Optional.empty(), Optional.of(history(true, change("!1", 1, 0, false))), Optional.empty());
            Measurement measured = evaluate(rule("\"minimumApprovals\":2,\"windowDays\":30,\"minimumRatio\":1"),
                    Map.of(1L, new ReviewRead(look(READ), evidence)));

            assertThat(measured.outcome()).isEqualTo(MeasurementOutcome.PASS);
            assertThat(measured.summary()).contains("settings: approval rules require 2 approvals, author approval prevented");
        }

        @Test
        @DisplayName("settings that allow the author's approval, a direct push, or fewer approvals prove nothing alone")
        void weakSettingsFallBackToTheHistory() {
            for (Settings weak : List.of(new Settings(1, false, true, "author may approve"),
                    new Settings(1, true, false, "push allowed"), new Settings(0, true, true, "no approval required"))) {
                ChangeReviewEvidence evidence = new ChangeReviewEvidence("gitlab", "group/app", "main", 30,
                        Optional.of(weak), Optional.empty(), Optional.of(history(true, change("!1", 1, 0, false))),
                        Optional.empty());
                Measurement measured = evaluate(EVERY_ONE, Map.of(1L, new ReviewRead(look(READ), evidence)));
                assertThat(measured.outcome()).as(weak.described()).isEqualTo(MeasurementOutcome.FAIL);
                assertThat(measured.repositories().getFirst().detail()).get(InstanceOfAssertFactories.STRING)
                        .contains(weak.described() + ", not enough on their own");
            }
        }

        @Test
        @DisplayName("no data, each way, with its reason in words: unlinked, unread, refused, stale, cut short, short, empty")
        void noData() {
            assertThat(evaluate(EVERY_ONE, Map.of()).reason()).contains(NoDataReason.NEVER_EXAMINED);
            Measurement unlinked = evaluate(EVERY_ONE, Map.of(1L, new ReviewUnlinked(look(READ),
                    "no forge connection imported it, and no discovered repository has its URL")));
            assertThat(unlinked.reason()).contains(NoDataReason.FORGE_UNLINKED);
            assertThat(unlinked.summary()).contains("no forge connection imported it");
            Measurement refused = evaluate(EVERY_ONE, Map.of(1L, new ReviewUnreadable(look(READ),
                    "GitHub refused the pull requests (HTTP 403): grant the token Pull requests: read")));
            assertThat(refused.reason()).contains(NoDataReason.FORGE_UNREADABLE);
            assertThat(refused.summary()).contains("Pull requests: read");
            assertThat(evaluate(EVERY_ONE, Map.of(1L, new ReviewUnreadable(look(NOW.minus(Duration.ofDays(3))), "x")))
                    .reason()).contains(NoDataReason.STALE);
            assertThat(evaluate(EVERY_ONE, Map.of(1L, new ReviewRead(look(NOW.minus(Duration.ofDays(3))),
                    evidence("gitlab", 30, history(true, change("!1", 1, 1, false))))))
                    .reason()).as("a reading older than maxAgeDays").contains(NoDataReason.STALE);
            Measurement unread = evaluate(EVERY_ONE, Map.of(1L, new ReviewRead(look(READ), new ChangeReviewEvidence("gitlab",
                    "group/app", "main", 30, Optional.empty(), Optional.of("HTTP 404"), Optional.empty(),
                    Optional.of("GitLab refused the merge requests (HTTP 403)")))));
            assertThat(unread.reason()).contains(NoDataReason.FORGE_UNREADABLE);
            assertThat(unread.summary()).contains("HTTP 403");
            assertThat(evaluate(EVERY_ONE, Map.of(1L, read(history(false, change("!1", 1, 1, false))))).reason())
                    .as("more merged than one reading takes").contains(NoDataReason.REVIEW_INCOMPLETE);
            assertThat(evaluate(rule("\"minimumApprovals\":1,\"windowDays\":60,\"minimumRatio\":1"),
                    Map.of(1L, read(history(true, change("!1", 1, 1, false))))).reason())
                    .as("a reading of thirty days for a rule of sixty").contains(NoDataReason.REVIEW_INCOMPLETE);
            assertThat(evaluate(EVERY_ONE, Map.of(1L, read(history(true, change("!1", 31, 0, false))))).reason())
                    .as("nothing merged in the window: none of none is not all").contains(NoDataReason.NO_CHANGE_MERGED);
        }

        @Test
        @DisplayName("one repository without data makes the line's no data, whatever the others say")
        void oneRepositoryWithout() {
            Map<Long, ReviewFacts> recorded = new HashMap<>();
            recorded.put(1L, read(history(true, change("!1", 1, 1, false))));
            Measurement measured = RuleEvaluation.evaluate(EVERY_ONE, facts(List.of(1L, 2L), recorded), NOW);
            assertThat(measured.outcome()).isEqualTo(MeasurementOutcome.NO_DATA);
            assertThat(measured.reason()).contains(NoDataReason.NEVER_EXAMINED);
        }

        @Test
        @DisplayName("the stored reading reads back as it was written")
        void storedForm() {
            ChangeReviewEvidence evidence = new ChangeReviewEvidence("github", "acme/api", "main", 30,
                    Optional.of(new Settings(1, true, true, "rulesets require 1 approval")), Optional.empty(),
                    Optional.empty(), Optional.of("HTTP 403"));
            assertThat(ChangeReviewEvidence.read(evidence.json())).isEqualTo(evidence);
            ChangeReviewEvidence other = evidence("gitlab", 30, history(true, change("!1", 1, 1, true)));
            assertThat(ChangeReviewEvidence.read(other.json())).isEqualTo(other);
            assertThatThrownBy(() -> new ChangeReviewEvidence("gitlab", "g/a", "main", 30, Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.of("x"))).isInstanceOf(IllegalArgumentException.class);
        }
    }

    // ---- The facts.

    private static Measurement evaluate(ChecklistRule rule, Map<Long, ReviewFacts> recorded) {
        return RuleEvaluation.evaluate(rule, facts(List.of(1L), recorded), NOW);
    }

    private static MeasurementFacts facts(List<Long> repositories, Map<Long, ReviewFacts> recorded) {
        return new MeasurementFacts(repositories, Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(),
                recorded);
    }

    private static Look look(Instant at) {
        return new Look(Source.FORGE_REVIEW, 7, at, Optional.of("ab".repeat(32)));
    }

    private static ReviewRead read(History history) {
        return read("gitlab", 30, history);
    }

    private static ReviewRead read(String forge, int windowDays, History history) {
        return new ReviewRead(look(READ), evidence(forge, windowDays, history));
    }

    private static ChangeReviewEvidence evidence(String forge, int windowDays, History history) {
        return new ChangeReviewEvidence(forge, "group/app", "main", windowDays, Optional.empty(),
                Optional.of("GitLab answers no approval settings (HTTP 404): Community Edition or Free tier"),
                Optional.of(history), Optional.empty());
    }

    private static History history(boolean complete, MergedChange... changes) {
        return new History(complete, List.of(changes));
    }

    private static MergedChange change(String reference, int daysBeforeReading, int peers, boolean authorApproved) {
        return new MergedChange(reference, READ.minus(Duration.ofDays(daysBeforeReading)), peers, authorApproved);
    }
}
