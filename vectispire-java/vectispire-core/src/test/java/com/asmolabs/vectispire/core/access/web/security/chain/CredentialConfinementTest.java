package com.asmolabs.vectispire.core.access.web.security.chain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.core.access.ApiKeyAuthService;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.web.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.access.web.security.ApiKeyRateLimitedException;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;

@DisplayName("credential confinement")
class CredentialConfinementTest {

    static class Routes {
        @AcceptsApiKey(ApiKeyScope.READ)
        public void read() {}
    }

    private static HandlerMethod readRoute() throws NoSuchMethodException {
        return new HandlerMethod(new Routes(), Routes.class.getMethod("read"));
    }

    private static void signInWith(UUID keyId) {
        UserEntity owner = new UserEntity();
        owner.setUsername("ci-owner");
        owner.setRole("viewer");
        SecurityContextHolder.getContext().setAuthentication(VectispirePrincipal.ofIntegration(
                new ApiKeyAuthService.Integration(UserView.of(owner), keyId, "ci", Set.of(ApiKeyScope.READ), Visibility.everything())));
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("a key past its budget is refused with the wait, and another key keeps its own budget")
    void eachKeyHasItsOwnBudget() throws Exception {
        CredentialConfinement confinement = new CredentialConfinement(2);
        HandlerMethod route = readRoute();
        UUID looping = UUID.randomUUID();

        signInWith(looping);
        for (int i = 0; i < 2; i++) {
            assertThat(confinement.preHandle(new MockHttpServletRequest(), new MockHttpServletResponse(), route)).isTrue();
        }
        assertThatThrownBy(() -> confinement.preHandle(new MockHttpServletRequest(), new MockHttpServletResponse(), route))
                .isInstanceOfSatisfying(ApiKeyRateLimitedException.class,
                        refused -> assertThat(refused.retryAfter()).isPositive());

        signInWith(UUID.randomUUID());
        assertThat(confinement.preHandle(new MockHttpServletRequest(), new MockHttpServletResponse(), route)).isTrue();
    }
}
