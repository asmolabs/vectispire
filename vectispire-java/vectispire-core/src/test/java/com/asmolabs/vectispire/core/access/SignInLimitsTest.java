package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the password throttle's settings")
class SignInLimitsTest {

    @Test
    @DisplayName("unset, zero or negative read as the shipped values — a ceiling of zero would refuse every sign-in")
    void anUnsetCeilingIsTheShippedOne() {
        for (SignInLimits limits : new SignInLimits[] {
                SignInLimits.DEFAULTS, new SignInLimits(-1, -1, -1, Duration.ofDays(-1)), new SignInLimits(0, 0, 0, Duration.ZERO)}) {
            assertThat(limits.failuresPerAccountFromClient()).isEqualTo(LoginThrottle.MAX_ATTEMPTS_PER_USER);
            assertThat(limits.failuresPerAccount()).isEqualTo(LoginThrottle.MAX_ATTEMPTS_PER_ACCOUNT);
            assertThat(limits.failuresPerClient()).isEqualTo(LoginThrottle.MAX_ATTEMPTS_PER_CLIENT);
            assertThat(limits.knownClientRetention()).isEqualTo(SignInLimits.DEFAULT_KNOWN_CLIENT_RETENTION);
        }
    }

    @Test
    @DisplayName("a value set is the value used")
    void aSetCeilingIsKept() {
        SignInLimits limits = new SignInLimits(3, 30, 10, Duration.ofDays(7));
        assertThat(limits.failuresPerAccountFromClient()).isEqualTo(3);
        assertThat(limits.failuresPerAccount()).isEqualTo(30);
        assertThat(limits.failuresPerClient()).isEqualTo(10);
        assertThat(limits.knownClientRetention()).isEqualTo(Duration.ofDays(7));
    }
}
