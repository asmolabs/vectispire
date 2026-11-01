package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * The password throttle's ceilings, {@code vectispire.sign-in.*} — see {@link LoginThrottle} for what
 * each one closes.
 *
 * <p>As {@code SecurityLimits} does, <b>an unset, zero or negative value reads as the shipped one</b>,
 * which lives on {@link LoginThrottle}: a ceiling of zero would refuse every sign-in, and an operator
 * who cleared a variable meant "the default", not "nobody gets in". The window stays
 * {@link LoginThrottle#WINDOW}: the attempts' purge and every counter read it, and a window moved for
 * one of them alone would be purged under another's.
 *
 * @param failuresPerAccountFromClient failures against one account or typed name from one client
 * @param failuresPerAccount failures against one account or typed name from every client — the soft
 *     budget, which a known client or a second factor goes past
 * @param failuresPerClient failures from one client across every account
 * @param knownClientRetention how long a client that signed in to an account stays known to it
 */
@Validated
@ConfigurationProperties("vectispire.sign-in")
public record SignInLimits(
        int failuresPerAccountFromClient,
        int failuresPerAccount,
        int failuresPerClient,
        Duration knownClientRetention) {

    /** Thirty days: a person who signs in once a month from the office keeps their exemption. */
    public static final Duration DEFAULT_KNOWN_CLIENT_RETENTION = Duration.ofDays(30);

    public static final SignInLimits DEFAULTS = new SignInLimits(0, 0, 0, null);

    public SignInLimits {
        failuresPerAccountFromClient = failuresPerAccountFromClient > 0
                ? failuresPerAccountFromClient
                : LoginThrottle.MAX_ATTEMPTS_PER_USER;
        failuresPerAccount = failuresPerAccount > 0 ? failuresPerAccount : LoginThrottle.MAX_ATTEMPTS_PER_ACCOUNT;
        failuresPerClient = failuresPerClient > 0 ? failuresPerClient : LoginThrottle.MAX_ATTEMPTS_PER_CLIENT;
        knownClientRetention = knownClientRetention == null || knownClientRetention.isNegative() || knownClientRetention.isZero()
                ? DEFAULT_KNOWN_CLIENT_RETENTION
                : knownClientRetention;
    }
}
