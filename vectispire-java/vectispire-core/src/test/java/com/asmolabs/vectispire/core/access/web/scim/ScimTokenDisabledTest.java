package com.asmolabs.vectispire.core.access.web.scim;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.VectispireContextTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/** A token left in the environment of an installation that switched SCIM off authenticates nobody. */
@TestPropertySource(properties = {"vectispire.scim.enabled=false", "vectispire.scim.token=scim-test-token-0123456789"})
@DisplayName("the SCIM provisioning token, with SCIM switched off")
class ScimTokenDisabledTest extends VectispireContextTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private FilterChainProxy securityFilterChain;

    @Test
    @DisplayName("authenticates nobody, even on /scim")
    void isRefused() throws Exception {
        MockMvcBuilders.webAppContextSetup(context).addFilters(securityFilterChain).build()
                .perform(get("/scim/v2/Users").header("Authorization", "Bearer scim-test-token-0123456789"))
                .andExpect(status().isUnauthorized());
    }
}
