package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.scheduling.CronSchedule;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.support.CronExpression;

/**
 * The cron parser the domain declares but is not allowed to see.
 *
 * <p>{@code CronSchedule} is a port for the reason stated on it: the scheduling rule must stay
 * testable with no clock and no framework, while parsing cron is a library's job. Spring ships
 * a perfectly good parser, and this is the one place it is reached.
 *
 * <p><b>UTC, not the machine's zone.</b> A fleet whose members sit in different zones must agree
 * on when "0 2 * * *" is, or the same target is scanned two or three times a night — once per
 * timezone represented, each instance convinced it was the only one due.
 */
public final class CronExpressions {

    private static final Logger log = LoggerFactory.getLogger(CronExpressions.class);

    private CronExpressions() {}

    /**
     * Empty when the target has no expression; {@link CronSchedule#NEVER} when it has an
     * unusable one.
     *
     * <p>The distinction matters and is the whole reason this is not one branch: an absent
     * expression means "run on the interval", while a broken one must <b>not</b> quietly start
     * running on a drifting interval the operator never asked for.
     */
    public static Optional<CronSchedule> parse(String expression) {
        if (expression == null || expression.isBlank()) {
            return Optional.empty();
        }
        try {
            CronExpression parsed = CronExpression.parse(normalize(expression));
            return Optional.of(from -> Optional.ofNullable(parsed.next(from.atZone(ZoneOffset.UTC)))
                    .map(next -> next.toInstant()));
        } catch (IllegalArgumentException notCron) {
            log.warn("Unusable cron expression \"{}\": this target will not be scheduled.", expression);
            return Optional.of(CronSchedule.NEVER);
        }
    }

    /** Whether an expression would be accepted, for the screen that validates one. */
    public static boolean isValid(String expression) {
        return expression != null && !expression.isBlank() && CronExpression.isValidExpression(normalize(expression));
    }

    /**
     * The five-field crontab form, in the six-field form Spring's parser requires.
     *
     * <p><b>The defect this fixes, because it is worth not reintroducing.</b> Everything in this
     * product taught the five-field form — both controllers' 400 says {@code Expected five fields,
     * for example "0 2 * * *"}, and the schedule form on screen says the same — while the parser
     * underneath requires six, seconds first. The example in the error message was itself rejected.
     * An operator following the instructions could not save a schedule, and the failure was silent
     * twice over: the fields were not editable from the interface at all until they were exposed,
     * and an unusable expression becomes {@link CronSchedule#NEVER} rather than an error, so the
     * target simply never ran — indistinguishable from one nobody had scheduled.
     *
     * <p>Five fields is the right contract to keep: it is what {@code crontab} means everywhere
     * else, and asking an operator to write a seconds column that must always be zero exposes a
     * quirk of one library as if it were part of the schedule.
     *
     * <p><b>Prepending {@code 0} and not {@code *}.</b> With a wildcard, "every day at 02:00" would
     * fire sixty times, once a second, through 02:00 — a schedule sixty times heavier than the one
     * that was written, which on a scan queue is not a rounding error.
     *
     * <p>Six fields are still accepted, untouched: anybody who found the real requirement by trial
     * and error has one stored, and rejecting it now would stop a schedule that is running.
     */
    private static String normalize(String expression) {
        String trimmed = expression.trim();
        // Split on any run of whitespace: a form field yields the odd double space, and a
        // five-field expression that read as six because of one would gain a seventh here.
        return trimmed.split("\\s+").length == 5 ? "0 " + trimmed : trimmed;
    }

    /** The next occurrence, for the screen that shows one. */
    public static Optional<Instant> nextOccurrence(String expression, Instant from) {
        return parse(expression).flatMap(schedule -> schedule.nextAfter(from));
    }
}
