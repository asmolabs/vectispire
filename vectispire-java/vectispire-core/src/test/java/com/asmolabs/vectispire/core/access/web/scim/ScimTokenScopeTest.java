package com.asmolabs.vectispire.core.access.web.scim;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.VectispireContextTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * The SCIM token provisions accounts through `/scim`, and does nothing else.
 *
 * <p>It is held by the identity provider — a third system, with its own operators and its own
 * breaches. It authenticated as an administrator with an unrestricted view, on every route: the
 * token that exists to create and deactivate accounts could also read the audit log, rewrite the
 * gate policy, issue API keys and change the settings.
 */
@TestPropertySource(properties = {"vectispire.scim.enabled=true", "vectispire.scim.token=scim-test-token-0123456789"})
@DisplayName("the SCIM provisioning token")
class ScimTokenScopeTest extends VectispireContextTest {

    private static final String SCIM = "Bearer scim-test-token-0123456789";

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private FilterChainProxy securityFilterChain;

    private MockMvc mvc;

    @BeforeEach
    void mvc() {
        mvc = MockMvcBuilders.webAppContextSetup(context).addFilters(securityFilterChain).build();
    }

    @Test
    @DisplayName("provisions through /scim")
    void reachesScim() throws Exception {
        mvc.perform(get("/scim/v2/Users").header("Authorization", SCIM)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("is nobody on the rest of the API, however administrative the route")
    void isNobodyElsewhere() throws Exception {
        for (String route : new String[] {"/api/v1/users", "/api/v1/audit-log", "/api/v1/api-keys", "/api/v1/settings"}) {
            mvc.perform(get(route).header("Authorization", SCIM)).andExpect(status().isUnauthorized());
        }
    }
}
