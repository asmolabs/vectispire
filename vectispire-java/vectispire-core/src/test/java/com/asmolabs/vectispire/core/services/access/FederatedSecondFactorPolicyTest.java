package com.asmolabs.vectispire.core.services.access;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A single sign-on skips the local TOTP; what the provider states about the second factor is
 * recorded, and required when the operator says so.
 */
@DisplayName("the second factor of a single sign-on")
class FederatedSecondFactorPolicyTest {

    private final FederatedSecondFactorPolicy lenient = new FederatedSecondFactorPolicy(false, "mfa,otp,hwk,fido", "");
    private final FederatedSecondFactorPolicy strict = new FederatedSecondFactorPolicy(true, "mfa,otp,hwk,fido", "gold");

    @Test
    @DisplayName("an amr value or a named acr level is evidence; a password alone is not")
    void whatCountsAsEvidence() {
        assertThat(lenient.evidence(List.of("pwd", "otp"), null)).contains("amr=pwd,otp");
        assertThat(strict.evidence(List.of("pwd"), "GOLD")).contains("acr=GOLD");
        assertThat(lenient.evidence(List.of("pwd"), "1")).isEmpty();
        assertThat(lenient.evidence(null, null)).isEmpty();
    }

    @Test
    @DisplayName("by default nothing is refused, but the absence is recorded")
    void lenientRecords() {
        assertThat(lenient.require(List.of("pwd"), null)).isEqualTo("no second factor stated by the provider");
    }

    @Test
    @DisplayName("required, a sign-on stating no second factor is refused with its own code")
    void strictRefuses() {
        assertThatThrownBy(() -> strict.require(List.of("pwd"), "1"))
                .isInstanceOf(ExternalIdentityService.SignInRefusedException.class)
                .extracting(e -> ((ExternalIdentityService.SignInRefusedException) e).refusal())
                .isEqualTo(ExternalIdentityService.Refusal.MFA_REQUIRED);
        assertThat(strict.require(List.of("pwd", "hwk"), null)).contains("amr=pwd,hwk");
    }
}
