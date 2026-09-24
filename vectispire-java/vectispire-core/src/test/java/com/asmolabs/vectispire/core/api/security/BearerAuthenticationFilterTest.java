package com.asmolabs.vectispire.core.api.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.AgentEntity;
import com.asmolabs.vectispire.core.persistence.ApiKeyEntity;
import com.asmolabs.vectispire.core.persistence.SessionEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.services.ApiKeyAuthService;
import com.asmolabs.vectispire.core.services.AuthService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.TestingAuthenticationToken;

/**
 * Who a bearer header turns into — the decision every other authorization rule starts from.
 *
 * <p>Reached until now only through the route tests, which exercise the happy paths; the refusals
 * below are the ones that matter and the ones nothing asserted.
 */
@DisplayName("the bearer authentication filter")
class BearerAuthenticationFilterTest {

    private final AuthService auth = mock(AuthService.class);
    private final ApiKeyAuthService apiKeys = mock(ApiKeyAuthService.class);
    private final VisibilityService visibility = mock(VisibilityService.class);
    private BearerAuthenticationFilter filter;

    @BeforeEach
    void wire() {
        SecurityContextHolder.clearContext();
        when(auth.resolve(any())).thenReturn(Optional.empty());
        when(apiKeys.resolve(anyString())).thenReturn(Optional.empty());
        filter = new BearerAuthenticationFilter(auth, apiKeys, visibility);
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("a session token becomes its account")
    void aSessionBecomesItsUser() throws Exception {
        SessionEntity session = session(7L);
        when(auth.resolve("Bearer s")).thenReturn(Optional.of(session));
        when(auth.activeUserOf(session)).thenReturn(Optional.of(user(7L, true)));

        assertThat(authenticate("Bearer s")).isInstanceOf(VectispirePrincipal.class)
                .satisfies(principal -> assertThat(((VectispirePrincipal) principal).user()).isPresent());
    }

    @Test
    @DisplayName("a deactivated account is nobody, and its session is closed on the spot")
    void aDeactivatedAccountIsRefused() throws Exception {
        SessionEntity session = session(7L);
        when(auth.resolve("Bearer s")).thenReturn(Optional.of(session));
        when(auth.activeUserOf(session)).thenReturn(Optional.empty());

        assertThat(authenticate("Bearer s")).isNull();
        verify(auth).revoke(session);
    }

    @Test
    @DisplayName("a key without the Bearer scheme is not accepted by accident")
    void theSchemeIsRequired() throws Exception {
        assertThat(authenticate("zsk_raw_key")).isNull();
        verify(apiKeys, never()).resolve(anyString());
    }

    @Test
    @DisplayName("an API key acts as an agent only with the agent scope")
    void onlyAnAgentKeyIsAnAgent() throws Exception {
        ApiKeyEntity key = new ApiKeyEntity();
        key.setId(UUID.randomUUID());
        when(apiKeys.resolve("zsk")).thenReturn(Optional.of(key));
        when(apiKeys.hasScope(key, ApiKeyScope.AGENT)).thenReturn(false);

        // A CI key can read and scan; it must not be able to claim work as an agent.
        assertThat(authenticate("Bearer zsk")).isNull();
    }

    @Test
    @DisplayName("an agent key becomes its agent, narrowed to the key's target")
    void anAgentKeyIsNarrowed() throws Exception {
        ApiKeyEntity key = new ApiKeyEntity();
        key.setId(UUID.randomUUID());
        key.setTargetKind("repository");
        key.setTargetId(5L);
        AgentEntity agent = new AgentEntity();
        agent.setId(UUID.randomUUID());
        Visibility narrowed = Visibility.only(java.util.List.of(new ScanTarget.Repository(5L)));
        when(apiKeys.resolve("zsk")).thenReturn(Optional.of(key));
        when(apiKeys.hasScope(key, ApiKeyScope.AGENT)).thenReturn(true);
        when(apiKeys.agentFor(key)).thenReturn(Optional.of(agent));
        when(visibility.restrictionOf("repository", 5L)).thenReturn(narrowed);

        VectispirePrincipal principal = (VectispirePrincipal) authenticate("Bearer zsk");
        assertThat(principal.agent()).contains(agent);
        assertThat(principal.credentialRestriction()).isSameAs(narrowed);
    }

    @Test
    @DisplayName("an authentication already in place is not replaced")
    void anExistingAuthenticationStands() throws Exception {
        TestingAuthenticationToken existing = new TestingAuthenticationToken("someone", null);
        SecurityContextHolder.getContext().setAuthentication(existing);

        assertThat(authenticate("Bearer s")).isSameAs(existing);
        verify(auth, never()).resolve(any());
    }

    private Authentication authenticate(String header) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/issues");
        request.addHeader("Authorization", header);
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private static SessionEntity session(long userId) {
        SessionEntity session = new SessionEntity();
        session.setUserId(userId);
        return session;
    }

    private static UserEntity user(long id, boolean active) {
        UserEntity user = new UserEntity();
        user.setId(id);
        user.setRole("USER");
        user.setIsActive(active);
        return user;
    }
}
