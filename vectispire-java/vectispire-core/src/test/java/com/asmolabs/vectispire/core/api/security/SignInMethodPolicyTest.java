package com.asmolabs.vectispire.core.api.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Which doors are open, and the one combination that must be refused.
 *
 * <p>Three of the four cases are arithmetic. The fourth — password sign-in asked to be off with
 * no identity provider behind it — is the one worth a test: honouring it leaves a deployment
 * nobody can sign into, and the person who would notice is the one who can no longer sign in to
 * notice anything.
 */
@DisplayName("the sign-in methods this deployment accepts")
class SignInMethodPolicyTest {

    private static final Optional<ClientRegistrationRepository> WITH_PROVIDER =
            Optional.of(mock(ClientRegistrationRepository.class));
    private static final Optional<ClientRegistrationRepository> WITHOUT_PROVIDER = Optional.empty();

    @Test
    @DisplayName("by default, a password works and single sign-on is absent")
    void theDefaultIsPasswordOnly() {
        SignInMethodPolicy policy = new SignInMethodPolicy(WITHOUT_PROVIDER, true);

        assertThat(policy.passwordAllowed()).isTrue();
        assertThat(policy.singleSignOnAvailable()).isFalse();
    }

    @Test
    @DisplayName("a provider does not remove the password on its own")
    void bothDoorsCanBeOpen() {
        // Adding an issuer must not silently change how everybody already signs in. Closing the
        // password door is a separate decision, and it is spelled out separately.
        SignInMethodPolicy policy = new SignInMethodPolicy(WITH_PROVIDER, true);

        assertThat(policy.passwordAllowed()).isTrue();
        assertThat(policy.singleSignOnAvailable()).isTrue();
    }

    @Test
    @DisplayName("with a provider, the password door can be closed")
    void theProviderCanCarryEverything() {
        SignInMethodPolicy policy = new SignInMethodPolicy(WITH_PROVIDER, false);

        assertThat(policy.passwordAllowed()).isFalse();
        assertThat(policy.singleSignOnAvailable()).isTrue();
    }

    @Test
    @DisplayName("without a provider, closing it is refused rather than honoured")
    void nobodyIsLockedOut() {
        // The dangerous configuration, and it is a plausible one: somebody sets
        // VECTISPIRE_PASSWORD_LOGIN=false while preparing the realm, and restarts before
        // VECTISPIRE_OIDC_ISSUER is in place. Honouring the request would leave a tool holding
        // every watched repository's deployment key with no way in at all — and no way to fix
        // it from the interface either.
        SignInMethodPolicy policy = new SignInMethodPolicy(WITHOUT_PROVIDER, false);

        assertThat(policy.passwordAllowed())
                .as("password sign-in stays on when it is the only door")
                .isTrue();
    }
}
