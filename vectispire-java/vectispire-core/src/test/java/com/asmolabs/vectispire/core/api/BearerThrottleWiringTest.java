package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * That the ceiling on refused bearer tokens is <b>in the chain that ships</b>.
 *
 * <p>{@code BearerRateLimitFilterTest} drives the filter with a mock chain, which proves the
 * counting and proves nothing about the assembly. The filter reads the security context <em>after</em>
 * calling through, to tell a refused token from one that resolved — a read that is only correct
 * because it runs inside Spring Security's chain and above the filter that clears the context. Get
 * that ordering wrong and every request looks refused, or none does, and the unit test stays green
 * either way.
 *
 * <p>This is the same lesson as the MFA lockout: a route can carry the right annotation and still
 * be unreachable, and only sending a real request through the real chain says which.
 */
@DisplayName("the bearer throttle, in the chain that ships")
class BearerThrottleWiringTest extends ApiTestBase {

    /** The shipped ceiling. Named here so a change to the default fails this test loudly. */
    private static final int CAPACITY = 60;

    @Test
    @DisplayName("an address spending its allowance on refused tokens is answered 429")
    void refusedTokensAreCounted() throws Exception {
        for (int attempt = 0; attempt < CAPACITY; attempt++) {
            mvc.perform(get("/api/v1/issues").header("Authorization", "Bearer zsk_not-a-real-key"))
                    .andExpect(status().isUnauthorized());
        }

        mvc.perform(get("/api/v1/issues").header("Authorization", "Bearer zsk_not-a-real-key"))
                .andExpect(status().isTooManyRequests())
                .andExpect(result -> {
                    if (result.getResponse().getHeader("Retry-After") == null) {
                        throw new AssertionError("A 429 with no Retry-After tells the caller to guess.");
                    }
                });
    }

    /**
     * The half that would make this control unusable if it were wrong.
     *
     * <p>A remote agent long-polls with a key that works, and the interface makes twenty calls to
     * paint a page. Counting those would throttle the deployment rather than whoever is sweeping.
     */
    @Test
    @DisplayName("a token that resolves is never counted, however many times it is used")
    void workingTokensAreNotCounted() throws Exception {
        String token = asAdmin();

        for (int attempt = 0; attempt < CAPACITY + 5; attempt++) {
            mvc.perform(authenticated(get("/api/v1/issues"), token)).andExpect(status().isOk());
        }
    }

    @Test
    @DisplayName("a request with no credentials at all is not a credential attempt")
    void anonymousRequestsAreNotCounted() throws Exception {
        for (int attempt = 0; attempt < CAPACITY + 5; attempt++) {
            mvc.perform(get("/api/v1/issues")).andExpect(status().isUnauthorized());
        }
    }
}
