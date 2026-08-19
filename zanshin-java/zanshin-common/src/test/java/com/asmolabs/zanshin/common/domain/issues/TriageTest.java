package com.asmolabs.zanshin.common.domain.issues;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.time.Period;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("triage rules")
class TriageTest {

    private static final Instant NOW = Instant.parse("2026-08-10T08:00:00Z");

    @Nested
    @DisplayName("recording a decision")
    class Decide {

        @Test
        @DisplayName("not_affected without a justification is refused, because VEX requires one")
        void notAffectedNeedsAJustification() {
            // Without one the statement carries no information, and an exported document
            // containing it would be invalid.
            Triage.Request request = new Triage.Request(TriageStatus.NOT_AFFECTED, "alice", null, null, null);

            assertThatThrownBy(() -> Triage.decide(request, NOW))
                    .isInstanceOf(InvalidTriageException.class)
                    .hasMessageContaining("VEX requirement");
        }

        @Test
        @DisplayName("the other statuses need no justification")
        void otherStatusesAreFree() {
            for (TriageStatus status : TriageStatus.values()) {
                if (status == TriageStatus.NOT_AFFECTED) {
                    continue;
                }
                assertThat(Triage.decide(new Triage.Request(status, "alice", null, null, null), NOW).status())
                        .isEqualTo(status);
            }
        }

        @Test
        @DisplayName("a blank comment is stored as absent, not as whitespace")
        void blankCommentIsAbsent() {
            Triage.Decision decision = Triage.decide(
                    new Triage.Request(TriageStatus.AFFECTED, "alice", null, "   ", null), NOW);

            assertThat(decision.comment()).isNull();
        }

        @Test
        @DisplayName("records who decided and when")
        void recordsTheDecider() {
            Triage.Decision decision = Triage.decide(
                    new Triage.Request(TriageStatus.AFFECTED, "alice", null, "Next release", null), NOW);

            assertThat(decision.triagedBy()).isEqualTo("alice");
            assertThat(decision.triagedAt()).isEqualTo(NOW);
        }
    }

    @Nested
    @DisplayName("the review date")
    class Expiry {

        @Test
        @DisplayName("is offered, not imposed")
        void isOptional() {
            // Deciding a component is simply not present needs no re-examination; "not
            // reachable in our configuration" badly does. Only the decider knows which they
            // just recorded.
            Triage.Decision decision = Triage.decide(
                    new Triage.Request(TriageStatus.NOT_AFFECTED, "alice", VexJustification.COMPONENT_NOT_PRESENT, null, null),
                    NOW);

            assertThat(decision.expiresAt()).isEmpty();
        }

        @Test
        @DisplayName("uses calendar arithmetic, so three months lands on the same day")
        void usesCalendarArithmetic() {
            // Adding 90 × 24 h instead drifts, and a review scheduled for the first of the
            // month arrives on the twenty-ninth of the one before.
            assertThat(Triage.expiryFrom(TriageStatus.NOT_AFFECTED, Period.ofMonths(3), NOW))
                    .contains(Instant.parse("2026-11-10T08:00:00Z"));
        }

        @Test
        @DisplayName("returning to under review clears it")
        void underReviewClearsTheDate() {
            // The issue is already in the queue; a date to bring it back there would fire on
            // nothing.
            assertThat(Triage.expiryFrom(TriageStatus.UNDER_REVIEW, Period.ofDays(30), NOW)).isEmpty();
        }

        @Test
        @DisplayName("a zero or negative delay is an error, not a silent never")
        void nonPositiveDelayIsRefused() {
            // Reading it as "never" would hide the caller's arithmetic mistake behind a
            // suppression that never expires.
            assertThatThrownBy(() -> Triage.expiryFrom(TriageStatus.AFFECTED, Period.ZERO, NOW))
                    .isInstanceOf(InvalidTriageException.class);
            assertThatThrownBy(() -> Triage.expiryFrom(TriageStatus.AFFECTED, Period.ofDays(-1), NOW))
                    .isInstanceOf(InvalidTriageException.class);
        }
    }

    @Nested
    @DisplayName("expiring a decision")
    class Expire {

        @Test
        @DisplayName("a decision is expired on its review date, not the day after")
        void expiresOnTheDate() {
            Instant due = NOW.plus(Period.ofDays(30));

            assertThat(Triage.isExpired(TriageStatus.NOT_AFFECTED, due, due)).isTrue();
            assertThat(Triage.isExpired(TriageStatus.NOT_AFFECTED, due, due.minusMillis(1))).isFalse();
        }

        @Test
        @DisplayName("an issue already under review never expires")
        void underReviewNeverExpires() {
            assertThat(Triage.isExpired(TriageStatus.UNDER_REVIEW, NOW.minusSeconds(1), NOW)).isFalse();
        }

        @Test
        @DisplayName("a decision with no review date never expires")
        void withoutADateNeverExpires() {
            // A suppression is a statement about a context, and contexts change — but a
            // decision that was never given a date was never promised a review.
            assertThat(Triage.isExpired(TriageStatus.NOT_AFFECTED, null, NOW)).isFalse();
        }

        @Test
        @DisplayName("expiring touches two fields and no others")
        void expiryKeepsTheEvidence() {
            // The justification, the comment, who decided and when are all kept. Erasing them
            // turns a scheduled review into an investigation from scratch, which is how a
            // review date becomes a field people stop filling in.
            assertThat(Triage.expire())
                    .isEqualTo(new Triage.Expiry(TriageStatus.UNDER_REVIEW, null));
        }
    }

    @Nested
    @DisplayName("the VEX vocabulary")
    class Vocabulary {

        @Test
        @DisplayName("parses the standard's spellings and refuses anything else")
        void parsesTheStandard() {
            assertThat(VexJustification.fromWireName("vulnerable_code_not_in_execute_path"))
                    .contains(VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH);
            assertThat(VexJustification.fromWireName("we looked and it is fine")).isEmpty();
            assertThat(VexJustification.fromWireName(null)).isEmpty();
        }
    }
}
