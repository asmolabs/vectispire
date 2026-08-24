package com.asmolabs.vectispire.core.api.security;

import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Component;

/**
 * Which ways in this deployment accepts.
 *
 * <p><b>What this is for, and it is not convenience.</b> Vectispire holds deployment keys for every
 * repository it watches, and a password is one factor. Adding a second factor to Vectispire itself
 * means enrolment, recovery codes, a reset path for whoever loses their phone — a feature, and a
 * good one. Delegating it costs a variable: an identity provider already does MFA, already
 * enforces the organisation's policy, and already knows how to un-enrol somebody who left. What
 * blocked that delegation was that the password stayed available beside the provider, so the
 * strongest requirement on the provider's side was optional in practice.
 *
 * <p>{@code VECTISPIRE_PASSWORD_LOGIN=false} closes the password door. Single sign-on then carries
 * whatever the realm requires, including a second factor Vectispire never sees.
 *
 * <p><b>The guard that matters more than the feature.</b> Closing the only door that works locks
 * everybody out of a security tool, and the person best placed to notice is the one who can no
 * longer sign in. So the request is honoured <em>only</em> when a provider is configured; asked
 * for without one, the password stays enabled and the reason is logged at error level. This is
 * the same decision `OidcConfiguration` makes by hanging on the issuer variable rather than on a
 * bean: an optional feature that is off must be absent, never present and refusing.
 *
 * <p><b>The way back, because there has to be one.</b> A realm that is unreachable, or a client
 * secret rotated without warning, leaves a deployment where nobody can sign in at all. The
 * escape is not a hidden account — a permanent back door is what
 * {@code vectispire.bootstrap} refuses to be — it is {@code VECTISPIRE_PASSWORD_LOGIN=true} and a
 * restart, by whoever can reach the process. That is deliberately an operator's act on the host
 * and not a button in the interface: a button would be reachable by exactly the attacker this
 * setting exists to stop.
 */
@Component
public class SignInMethodPolicy {

    private static final Logger log = LoggerFactory.getLogger(SignInMethodPolicy.class);

    private final boolean singleSignOn;
    private final boolean password;

    public SignInMethodPolicy(
            Optional<ClientRegistrationRepository> providers,
            @Value("${vectispire.oidc.password-login:true}") boolean passwordRequested) {

        this.singleSignOn = providers.isPresent();
        this.password = passwordRequested || !singleSignOn;

        if (!passwordRequested && !singleSignOn) {
            log.error("VECTISPIRE_PASSWORD_LOGIN is false and no identity provider is configured, so password sign-in "
                    + "stays enabled: honouring it would leave no way to sign in at all. Set VECTISPIRE_OIDC_ISSUER, "
                    + "or leave password sign-in on.");
        }
    }

    /** Whether a password may be exchanged for a session at all. */
    public boolean passwordAllowed() {
        return password;
    }

    public boolean singleSignOnAvailable() {
        return singleSignOn;
    }
}
