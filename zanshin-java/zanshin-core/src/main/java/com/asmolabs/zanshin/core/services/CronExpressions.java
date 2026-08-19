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
            CronExpression parsed = CronExpression.parse(expression.trim());
            return Optional.of(from -> Optional.ofNullable(parsed.next(from.atZone(ZoneOffset.UTC)))
                    .map(next -> next.toInstant()));
        } catch (IllegalArgumentException notCron) {
            log.warn("Unusable cron expression \"{}\": this target will not be scheduled.", expression);
            return Optional.of(CronSchedule.NEVER);
        }
    }

    /** Whether an expression would be accepted, for the screen that validates one. */
    public static boolean isValid(String expression) {
        return CronExpression.isValidExpression(expression == null ? null : expression.trim());
    }

    /** The next occurrence, for the screen that shows one. */
    public static Optional<Instant> nextOccurrence(String expression, Instant from) {
        return parse(expression).flatMap(schedule -> schedule.nextAfter(from));
    }
}
