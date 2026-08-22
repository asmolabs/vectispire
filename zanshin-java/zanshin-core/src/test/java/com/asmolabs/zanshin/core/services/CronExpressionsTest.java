package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The cron expressions this product says it accepts.
 *
 * <p><b>The defect this file was written for.</b> Every message and every screen taught the
 * five-field crontab form — the controllers' own 400 says {@code Expected five fields, for example
 * "0 2 * * *"} — and the parser underneath is Spring's, which requires <b>six</b>, seconds first.
 * So the example in the error message was itself rejected, and an operator following the
 * instructions on screen could not save a schedule at all.
 *
 * <p>It stayed invisible for two reasons worth naming. The fields were not editable from the
 * interface until now, so almost nobody reached the validator. And an unusable expression parses to
 * {@code CronSchedule.NEVER} rather than throwing — which is the right behaviour, and which meant
 * the target simply never ran, silently, looking exactly like a target nobody had scheduled.
 */
@DisplayName("cron expressions")
class CronExpressionsTest {

    @Test
    @DisplayName("the five-field form the screens teach is accepted")
    void acceptsTheDocumentedForm() {
        // The literal example in both controllers' error message. It has to work, or the message
        // is instructions nobody can follow.
        assertThat(CronExpressions.isValid("0 2 * * *")).isTrue();
        assertThat(CronExpressions.isValid("0 */6 * * *")).isTrue();
        assertThat(CronExpressions.isValid("30 3 * * 1")).isTrue();
    }

    @Test
    @DisplayName("the six-field form still works, so nothing already stored breaks")
    void stillAcceptsSixFields() {
        // Anybody who found the real requirement by trial and error has one of these in a column.
        // Rejecting it now would stop a schedule that was running.
        assertThat(CronExpressions.isValid("0 0 2 * * *")).isTrue();
    }

    @Test
    @DisplayName("the five-field form means what crontab means: seconds are zero")
    void fiveFieldsStartOnTheMinute() {
        // 02:00:00, not 02:00:30 — otherwise "every day at 02:00" would fire at whatever second
        // the translation happened to pick.
        Optional<Instant> next = CronExpressions.nextOccurrence("0 2 * * *", Instant.parse("2026-08-19T00:00:00Z"));

        assertThat(next).contains(Instant.parse("2026-08-19T02:00:00Z"));
    }

    @Test
    @DisplayName("the two forms mean the same thing")
    void bothFormsAgree() {
        Instant from = Instant.parse("2026-08-19T00:00:00Z");

        // The translation is a translation, not an approximation: if these differed, an operator
        // rewriting their expression in the other form would silently change when scans run.
        assertThat(CronExpressions.nextOccurrence("0 2 * * *", from))
                .isEqualTo(CronExpressions.nextOccurrence("0 0 2 * * *", from));
    }

    @Test
    @DisplayName("nonsense is refused rather than translated into something plausible")
    void refusesNonsense() {
        // The danger of accepting a second field count is accepting a *wrong* one: four fields must
        // not become a valid expression by having a zero prepended.
        assertThat(CronExpressions.isValid("0 2 * *")).isFalse();
        assertThat(CronExpressions.isValid("not a cron")).isFalse();
        assertThat(CronExpressions.isValid("99 99 * * *")).isFalse();
    }

    @Test
    @DisplayName("an unusable expression schedules nothing rather than falling back to the interval")
    void unusableMeansNever() {
        // The distinction the parser exists for: absent means "use the interval", broken must not
        // quietly start running on a drifting interval nobody asked for.
        assertThat(CronExpressions.parse("")).isEmpty();
        assertThat(CronExpressions.parse("not a cron"))
                .get()
                .satisfies(schedule -> assertThat(schedule.nextAfter(Instant.now())).isEmpty());
    }
}
