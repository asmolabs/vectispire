package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.scheduling.Schedules;
import com.asmolabs.vectispire.common.domain.scheduling.Schedules.InForce;
import com.asmolabs.vectispire.common.domain.scheduling.Schedules.Schedulable;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Duration;
import java.time.Instant;
import org.springframework.stereotype.Service;

/**
 * A target's schedule as {@link Schedules} reads it, and the installation's default beside it.
 *
 * <p><b>One translation from the row to the rule.</b> The scheduler deciding what is due, the lists
 * saying what is in force and a checklist rule asking whether a repository runs often enough all
 * read the same four columns and the same setting; three copies of "an interval of zero is no
 * interval" are three chances to disagree about which targets run.
 */
@Service
public class TargetSchedules {

    private final SettingsService settings;

    public TargetSchedules(SettingsService settings) {
        this.settings = settings;
    }

    /** The default interval in force now; zero when an administrator has set none. */
    public Duration defaultInterval() {
        return Duration.ofDays(settings.asInt(Setting.SCAN_DEFAULT_INTERVAL_DAYS));
    }

    public static Schedulable of(RepositoryView repository) {
        return schedulable(new ScanTarget.Repository(repository.id()), repository.scanManualOnly(),
                repository.scanCron(), repository.scanIntervalMinutes(), repository.lastScheduledScanAt());
    }

    public static Schedulable of(ContainerView container) {
        return schedulable(new ScanTarget.Container(container.id()), container.scanManualOnly(),
                container.scanCron(), container.scanIntervalMinutes(), container.lastScheduledScanAt());
    }

    public static InForce inForce(RepositoryView repository, Duration defaultInterval) {
        return Schedules.inForce(of(repository), defaultInterval);
    }

    public static InForce inForce(ContainerView container, Duration defaultInterval) {
        return Schedules.inForce(of(container), defaultInterval);
    }

    private static Schedulable schedulable(
            ScanTarget target, boolean manualOnly, String cron, Integer intervalMinutes, Instant lastScheduledAt) {
        return new Schedulable(
                target,
                manualOnly,
                CronExpressions.parse(cron),
                intervalMinutes == null ? Duration.ZERO : Duration.ofMinutes(intervalMinutes),
                lastScheduledAt);
    }
}
