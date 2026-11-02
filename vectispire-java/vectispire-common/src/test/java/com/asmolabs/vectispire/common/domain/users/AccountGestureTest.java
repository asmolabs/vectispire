package com.asmolabs.vectispire.common.domain.users;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** The gestures' stored names: a row written by one version is read by the next. */
@DisplayName("an account gesture's stored name")
class AccountGestureTest {

    @Test
    @DisplayName("is its lowercase name, and reads back")
    void roundTrips() {
        assertThat(AccountGesture.PASSWORD_RESET.wireName()).isEqualTo("password_reset");
        for (AccountGesture gesture : AccountGesture.values()) {
            assertThat(AccountGesture.fromWireName(gesture.wireName())).contains(gesture);
        }
        assertThat(AccountGesture.fromWireName("PASSWORD_RESET")).isEmpty();
    }
}
