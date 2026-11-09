package com.asmolabs.vectispire.core.scanning.internal;

import java.time.Duration;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * @param lease how long a lease holds without renewal. Comfortably longer than the tick that
 *     renews it, so a slow tick does not hand the work to somebody else — and short enough that
 *     a dead leader is replaced in a couple of minutes rather than an hour. A second at least: a
 *     bare number binds as milliseconds, so {@code 180} — the unit forgotten — would be a lease that
 *     lapses before its first renewal, and every instance would take the jobs in turn
 */
@Validated
@ConfigurationProperties("vectispire.leader")
public record LeaderProperties(
        @DefaultValue("180s")
                @DurationMin(
                        seconds = 1,
                        message = "must be at least one second; a bare number is read as milliseconds (write 60s, 20m or 12h)")
                Duration lease) {}
