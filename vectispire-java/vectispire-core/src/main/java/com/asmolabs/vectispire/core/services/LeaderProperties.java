package com.asmolabs.vectispire.core.services;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * @param lease how long a lease holds without renewal. Comfortably longer than the tick that
 *     renews it, so a slow tick does not hand the work to somebody else — and short enough that
 *     a dead leader is replaced in a couple of minutes rather than an hour
 */
@ConfigurationProperties("vectispire.leader")
public record LeaderProperties(@DefaultValue("180s") Duration lease) {}
