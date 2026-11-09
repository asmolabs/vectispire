package com.asmolabs.vectispire.common.domain.users;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Which roles have a say in a four-eyes decision, and so which account changes wait for a second
 * administrator (#126, option 2). The governor approves no triage and still approves account requests: left
 * out, a governor could be created by one administrator alone and approve that administrator's requests.
 */
@DisplayName("the roles that approve")
class RoleApprovesTest {

    @Test
    @DisplayName("are the triage approvers and the administrators, and nobody else")
    void approversAndAdministrators() {
        assertThat(Arrays.stream(Role.values()).filter(Role::approves))
                .containsExactlyInAnyOrder(Role.SUPERUSER, Role.ADMIN, Role.CISO, Role.SECURITY_CHAMPION);
        assertThat(Role.AUDITOR.approves()).isFalse();
        assertThat(Role.USER.approves()).isFalse();
    }
}
