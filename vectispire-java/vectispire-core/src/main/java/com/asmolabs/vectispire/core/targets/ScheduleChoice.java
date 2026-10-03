package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;

/**
 * A target's schedule as an operator sets it — manual only, a cron expression, an interval, or none
 * of them, which is the installation's default — applied to what the row held.
 *
 * <p><b>Manual only and a schedule exclude each other, and the row never holds both.</b> Choosing
 * manual only clears the interval and the expression; naming an interval or an expression without
 * saying anything of manual only leaves it, since that is what asking for a schedule means; naming
 * both in one request is refused, because there is no reading of it that is not a guess. A row
 * carrying a cron expression the scheduler ignores is a row that tells its reader the wrong thing.
 *
 * <p>The update conventions are the routes': {@code null} leaves a field alone, an empty expression
 * clears it, and an interval of zero clears the interval — stored as {@code null}, the one spelling
 * of "not set", so that a zero is not mistaken for a choice.
 */
record ScheduleChoice(boolean manualOnly, Integer intervalMinutes, String cron) {

    static final ScheduleChoice NONE = new ScheduleChoice(false, null, null);

    /**
     * @param manualOnly the request's choice, or {@code null} for none
     * @param intervalMinutes minutes, zero to clear, or {@code null} to leave alone
     * @param cron an expression, empty to clear, or {@code null} to leave alone
     */
    ScheduleChoice apply(Boolean manualOnly, Integer intervalMinutes, String cron) {
        if (intervalMinutes != null && intervalMinutes < 0) {
            throw new InvalidInputException("The rescan interval is a number of minutes, zero or more; zero clears it.");
        }
        String expression = cron == null ? null : RepositoryAdministrationService.validatedCron(cron);
        boolean namesSchedule = (intervalMinutes != null && intervalMinutes > 0) || expression != null;
        if (Boolean.TRUE.equals(manualOnly) && namesSchedule) {
            throw new InvalidInputException(
                    "A target set to manual only takes no interval and no cron expression: choose one or the other.");
        }
        boolean manual = manualOnly != null ? manualOnly : !namesSchedule && this.manualOnly;
        if (manual) {
            return new ScheduleChoice(true, null, null);
        }
        return new ScheduleChoice(
                false,
                intervalMinutes == null ? this.intervalMinutes : (intervalMinutes == 0 ? null : intervalMinutes),
                cron == null ? this.cron : expression);
    }
}
