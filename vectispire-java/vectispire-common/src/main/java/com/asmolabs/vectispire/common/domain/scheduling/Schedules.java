package com.asmolabs.vectispire.common.domain.scheduling;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * When a target is due for a rescan.
 *
 * <p>The interval, the cron expression and the last scheduled time have existed on targets from
 * the start, and the screen collects an interval for every target added. <b>Nothing read
 * them</b>, so every scan was manual — in a tool whose entire premise is that new
 * vulnerabilities appear in code that has not changed. A weekly manual scan is not posture
 * management.
 *
 * <p><b>The cron expression wins over the interval.</b> It is the more specific of the two, and
 * an interval cannot say "every night at two": it drifts a little each round, because the next
 * one is counted from the last, so a scan set for the quiet hours ends up running in the middle
 * of the day. For a job that starts containers and pulls whole registries, the hour is not a
 * detail. Clearing the expression returns the target to its interval.
 *
 * <p><b>Manual only wins over both, and neither means the default</b> — see {@link Mode}.
 *
 * <p>Pure: the policy is tested with no database and no real clock.
 */
public final class Schedules {

    private Schedules() {}

    /**
     * The default rescan interval of an installation that has not chosen one: weekly. The cadence a
     * "weekly posture report" assumes, and short enough that an advisory published on Monday is matched
     * against an unchanged dependency within the week.
     */
    public static final Duration DEFAULT_INTERVAL = Duration.ofDays(7);

    /**
     * Which of the four ways a target can be scheduled is in force — said once, here, so that the
     * scheduler, the lists and a checklist rule cannot each hold an opinion of their own.
     *
     * <p><b>Manual only is a choice and not an absence</b> (0.11.0). Until then a target with neither
     * an interval nor a cron expression was never rescanned, and that was what every target added
     * through the forms got, since they left both fields empty: most of an estate was examined once and
     * never again. "Not set" now means {@link #DEFAULT} — the installation's default interval — and
     * an operator who really wants no rescan says so with {@link #MANUAL}, which wins over everything
     * else the row carries.
     */
    public enum Mode {
        /** Never rescanned automatically, whatever the default says. */
        MANUAL("manual"),
        /** On the target's cron expression, which wins over its interval. */
        CRON("cron"),
        /** On the target's own interval, counted from its last round. */
        INTERVAL("interval"),
        /** On the installation's default interval, at a moment of its own within it. */
        DEFAULT("default");

        private final String wireName;

        Mode(String wireName) {
            this.wireName = wireName;
        }

        public String wireName() {
            return wireName;
        }
    }

    /**
     * A target as the scheduling rule sees it.
     *
     * @param target which target — it decides where in the default interval the target falls
     * @param manualOnly the operator's explicit "never rescan this"
     * @param cron the parsed expression, when the target has one
     * @param interval the target's own interval; empty or zero means "not set", i.e. the default
     * @param lastScheduledAt when the scheduler last picked this target up, if ever
     */
    public record Schedulable(
            ScanTarget target, boolean manualOnly, Optional<CronSchedule> cron, Duration interval, Instant lastScheduledAt) {

        public Mode mode() {
            if (manualOnly) {
                return Mode.MANUAL;
            }
            if (cron.isPresent()) {
                return Mode.CRON;
            }
            return positive(interval) ? Mode.INTERVAL : Mode.DEFAULT;
        }
    }

    /**
     * The schedule in force, as a list shows it.
     *
     * @param interval how often the target runs: its own interval, or the default under
     *     {@link Mode#DEFAULT}. Empty for a cron expression, for manual only, and for the default when
     *     the installation has none — a target that, in effect, is not rescanned
     */
    public record InForce(Mode mode, Optional<Duration> interval) {}

    public static InForce inForce(Schedulable target, Duration defaultInterval) {
        Mode mode = target.mode();
        return new InForce(mode, switch (mode) {
            case MANUAL, CRON -> Optional.empty();
            case INTERVAL -> Optional.of(target.interval());
            case DEFAULT -> positive(defaultInterval) ? Optional.of(defaultInterval) : Optional.empty();
        });
    }

    /**
     * Is this target due, according to the schedule in force?
     *
     * @param defaultInterval the installation's default; zero means "no default", which leaves a
     *     target with no schedule of its own unscheduled, as every version before 0.11.0 did
     */
    public static boolean isDue(Schedulable target, Duration defaultInterval, Instant now) {
        return switch (target.mode()) {
            case MANUAL -> false;
            case CRON -> cronDue(target.cron().orElseThrow(), target.lastScheduledAt(), now);
            case INTERVAL -> intervalDue(target.interval(), target.lastScheduledAt(), now);
            case DEFAULT -> defaultDue(target.target(), defaultInterval, target.lastScheduledAt(), now);
        };
    }

    /**
     * Has a target's interval elapsed?
     *
     * <p>A target with no interval is never scheduled by this rule. A target never scanned
     * automatically is <b>due immediately</b>: otherwise switching the scheduler on would leave
     * it waiting a full interval before its first round, which is a day of silence with a daily
     * interval, and reads as a broken scheduler.
     *
     * <p>Unchanged by the default interval: an explicit interval still counts from the last round,
     * and drifts with it, exactly as it always has.
     */
    public static boolean intervalDue(Duration interval, Instant lastScheduledAt, Instant now) {
        if (!positive(interval)) {
            return false;
        }
        if (lastScheduledAt == null) {
            return true;
        }
        return !now.isBefore(lastScheduledAt.plus(interval));
    }

    /**
     * Is a target under the default interval due?
     *
     * <p><b>Each target has its own moment in the interval</b>, and is due when that moment has come
     * round since its last round. The moments are the instants {@code offset + k × interval} counted
     * from the epoch, the offset being {@link #offset} — so they are spread over the interval, the same
     * on every tick and every instance, and stored nowhere.
     *
     * <p><b>Why not the explicit interval's rule.</b> Counted from the last round, every target whose
     * last round is the same instant stays together for ever — and on the upgrade to 0.11.0 that is
     * nearly the whole estate, whose targets had no schedule and become due at once: a week's scans in
     * the first minute, and again the same minute every week after. Anchored on its slot, a target
     * runs once per interval whenever the last round happened, and a crowd that started together
     * comes apart at the first round. The upgrade's own migration (V70) stamps those targets with the
     * upgrade instant, so their first round is their slot in the following week rather than now.
     *
     * <p>A target never picked up is due at once, as under an explicit interval: one added after the
     * upgrade should not wait up to a week for its first look.
     */
    public static boolean defaultDue(ScanTarget target, Duration defaultInterval, Instant lastScheduledAt, Instant now) {
        if (!positive(defaultInterval)) {
            return false;
        }
        if (lastScheduledAt == null) {
            return true;
        }
        return lastScheduledAt.isBefore(latestSlot(target, defaultInterval, now));
    }

    /** The last moment at or before {@code now} at which this target's default round falls. */
    static Instant latestSlot(ScanTarget target, Duration interval, Instant now) {
        long period = Math.max(1, interval.toSeconds());
        long seconds = now.getEpochSecond();
        return Instant.ofEpochSecond(seconds - Math.floorMod(seconds - offset(target, interval).toSeconds(), period));
    }

    /**
     * Where in the default interval this target falls: a whole number of seconds in {@code [0, interval)}.
     *
     * <p>Derived from the kind and the id, and from nothing that changes — a name or a URL would move
     * the target in the week each time it is edited. The kind enters so that repository 7 and image 7
     * do not share a moment. The mixing function is SplitMix64's finaliser, so that consecutive ids
     * — which is what an estate registered in one sitting has — land far apart rather than one second
     * apart. <b>Changing this formula moves every target once</b>: a target whose new moment falls
     * before its old one in the current interval runs early, one whose new moment falls after runs late
     * — a single uneven week, which is why it is not changed lightly.
     */
    public static Duration offset(ScanTarget target, Duration interval) {
        long seed = switch (target) {
            case ScanTarget.Repository repository -> repository.id() * 2;
            case ScanTarget.Container container -> container.id() * 2 + 1;
        };
        return Duration.ofSeconds(Math.floorMod(mix(seed), Math.max(1, interval.toSeconds())));
    }

    private static long mix(long value) {
        long z = value + 0x9e3779b97f4a7c15L;
        z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
        z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
        return z ^ (z >>> 31);
    }

    private static boolean positive(Duration duration) {
        return duration != null && !duration.isZero() && !duration.isNegative();
    }

    /**
     * Has an occurrence passed since the last scheduled round?
     *
     * <p><b>Computed from the last round and not from now</b>, so a round running late — a
     * restart, a slow pass — catches up the occurrence it missed instead of skipping to the
     * next one. A nightly scan must not be lost because the process was restarting at two.
     */
    public static boolean cronDue(CronSchedule cron, Instant lastScheduledAt, Instant now) {
        if (cron == null) {
            return false;
        }
        if (lastScheduledAt == null) {
            // Due immediately — but only once the expression is known to fire at all. Asking
            // that *before* taking the shortcut is what stops the one target whose
            // configuration is broken from being the only one to fire unasked.
            return cron.nextAfter(now).isPresent();
        }
        return cron.nextAfter(lastScheduledAt).map(next -> !next.isAfter(now)).orElse(false);
    }

    /** The most occurrences {@link #runsAtLeastEvery} walks before it stops believing a schedule. */
    static final int CADENCE_STEPS = 20_000;

    /**
     * Whether a target's schedule runs it at least once in every window of {@code period} from
     * {@code now} on — what a dependency rule asking for a matching schedule reads (decision 0032 §6).
     *
     * <p><b>The schedule in force, as {@link #isDue} reads it</b>: manual only does not run; the cron
     * expression wins; without one, the target's interval or else the installation's default, which
     * runs at least as often as the period when it is at most the period. A target under a default of
     * zero — none — does not.
     *
     * <p><b>Every gap, not the next one.</b> "Every minute of the first five days of the month" fires
     * often and then waits twenty-five days; a check of the next occurrence alone would call it daily.
     * So the occurrences are walked over two periods, and at least a sixty-two-day horizon so that a
     * monthly shape shows its longest gap, each gap compared with the period. A schedule whose walk
     * exceeds {@value #CADENCE_STEPS} occurrences before the horizon is not believed: the answer errs
     * towards "not established", which a rule reads as unmet rather than as a pass nobody checked.
     */
    public static boolean runsAtLeastEvery(Schedulable target, Duration defaultInterval, Duration period, Instant now) {
        InForce inForce = inForce(target, defaultInterval);
        return switch (inForce.mode()) {
            case MANUAL -> false;
            case CRON -> runsAtLeastEvery(target.cron(), Duration.ZERO, period, now);
            // The default's rounds fall on fixed slots one interval apart, so the interval is the gap.
            case INTERVAL, DEFAULT -> runsAtLeastEvery(Optional.empty(), inForce.interval().orElse(Duration.ZERO), period, now);
        };
    }

    /** The same question for a cron expression, or else an interval — the rule above once the mode is decided. */
    public static boolean runsAtLeastEvery(Optional<CronSchedule> cron, Duration interval, Duration period, Instant now) {
        if (period == null || period.isZero() || period.isNegative()) {
            return false;
        }
        if (cron.isEmpty()) {
            return interval != null && !interval.isZero() && !interval.isNegative() && interval.compareTo(period) <= 0;
        }
        Duration span = period.multipliedBy(2);
        Instant horizon = now.plus(span.compareTo(Duration.ofDays(62)) < 0 ? Duration.ofDays(62) : span);
        Instant from = now;
        for (int step = 0; step < CADENCE_STEPS; step++) {
            Optional<Instant> next = cron.get().nextAfter(from);
            if (next.isEmpty() || Duration.between(from, next.get()).compareTo(period) > 0) {
                return false;
            }
            if (next.get().isAfter(horizon)) {
                return true;
            }
            from = next.get();
        }
        return false;
    }
}
