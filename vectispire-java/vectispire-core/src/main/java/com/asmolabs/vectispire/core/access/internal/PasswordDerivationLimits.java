package com.asmolabs.vectispire.core.access.internal;

import com.asmolabs.vectispire.common.domain.crypto.DerivationGate;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * The bound on password derivations running at once, {@code vectispire.sign-in.derivations.*} — see
 * {@link DerivationGate} for what it closes, and {@link PasswordDerivationBound} for where it is put in
 * force.
 *
 * <p>As every ceiling here, <b>an unset, zero or negative value reads as the shipped one</b>, which
 * lives on {@link DerivationGate}: a bound of zero would refuse every sign-in.
 *
 * @param concurrent derivations at once; zero sizes it from the processors and the heap
 * @param queueWait how long a derivation waits for its turn before the request is answered {@code 503}
 */
@Validated
@ConfigurationProperties("vectispire.sign-in.derivations")
public record PasswordDerivationLimits(int concurrent, Duration queueWait) {}
