package com.asmolabs.vectispire.core.access.internal;

import com.asmolabs.vectispire.common.domain.crypto.DerivationGate;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Puts the deployment's {@link PasswordDerivationLimits} in force on {@link PasswordHasher}.
 *
 * <p><b>A bean of its own, at startup</b>, so the bound holds before the first request is served and
 * whether or not anything asks for it: the hasher is called statically from every place that derives
 * — a sign-in, an API key, a password change, the bootstrap — and none of them is handed the bound.
 */
@Component
class PasswordDerivationBound {

    private static final Logger log = LoggerFactory.getLogger(PasswordDerivationBound.class);

    PasswordDerivationBound(PasswordDerivationLimits limits) {
        DerivationGate gate = new DerivationGate(limits.concurrent(), limits.queueWait());
        PasswordHasher.bound(gate);
        log.info("Password derivations: at most {} at once, waiting up to {} ms for a turn.",
                gate.permits(), gate.await().toMillis());
    }
}
