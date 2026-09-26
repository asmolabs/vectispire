package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.Users;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import java.util.List;
import java.util.Map;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Integration API keys over HTTP (decision 0024): a key acts for its account, narrowed by its
 * target, on the routes that accept a key and for the scopes it holds — and nowhere else.
 */
@DisplayName("integration API keys")
class ApiKeyIntegrationRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Users users;

    @Autowired
    private Containers containers;

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + "-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private String issue(String ownerToken, Map<String, Object> body) throws Exception {
        String response = mvc.perform(authenticated(post("/api/v1/api-keys"), ownerToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(response).get("secret").asText();
    }

    @Test
    @DisplayName("reads with its account's authority, narrowed to the target it was restricted to")
    void aRestrictedReadKeySeesItsTargetOnly() throws Exception {
        long mine = repository("mine");
        long other = repository("other");
        String key = issue(asAdmin(), Map.of("name", "ci", "scopes", List.of("read"),
                "target_kind", "repository", "target_id", mine));

        String listed = mvc.perform(authenticated(get("/api/v1/repositories"), key))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(json.readTree(listed).findValues("id").stream().map(node -> node.asLong()).toList())
                .contains(mine)
                .doesNotContain(other);
    }

    @Test
    @DisplayName("is refused on a route that does not accept keys, and for a scope it does not hold")
    void onlyTheRoutesAndScopesItWasGiven() throws Exception {
        long target = repository("scoped");
        String readOnly = issue(asAdmin(), Map.of("name", "reader", "scopes", List.of("read")));

        // An administrative route: the key's account is an administrator, and that is exactly why
        // the confinement cannot be left to the role markers.
        mvc.perform(authenticated(get("/api/v1/users"), readOnly))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.detail").value(Matchers.containsString("does not accept an API key")));
        mvc.perform(authenticated(post("/api/v1/repositories/" + target + "/scan"), readOnly))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.detail").value(Matchers.containsString("lacks the scan scope")));

        String scanner = issue(asAdmin(), Map.of("name", "scanner", "scopes", List.of("scan")));
        mvc.perform(authenticated(post("/api/v1/repositories/" + target + "/scan"), scanner))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("a restricted scan key triggers its own target only, and another answers as absent")
    void aRestrictedScanKeyTriggersItsTargetOnly() throws Exception {
        long mine = repository("scan-mine");
        long other = repository("scan-other");
        String key = issue(asAdmin(), Map.of("name", "gate", "scopes", List.of("scan"),
                "target_kind", "repository", "target_id", mine));

        mvc.perform(authenticated(post("/api/v1/repositories/" + mine + "/scan"), key)).andExpect(status().isOk());
        mvc.perform(authenticated(post("/api/v1/repositories/" + other + "/scan"), key)).andExpect(status().isNotFound());
        ContainerEntity image = new ContainerEntity();
        image.setImageName("team/scan-other");
        image.setTag("latest");
        long otherImage = containers.save(image).getId();
        mvc.perform(authenticated(post("/api/v1/containers/" + otherImage + "/scan"), key)).andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("is also read from X-API-Key, where a session token is not")
    void theAliasHeaderCarriesKeysOnly() throws Exception {
        String session = asAdmin();
        String key = issue(session, Map.of("name", "alias", "scopes", List.of("read")));

        mvc.perform(get("/api/v1/issues").header("X-API-Key", key)).andExpect(status().isOk());
        mvc.perform(get("/api/v1/issues").header("X-API-Key", session)).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("stops working with its account")
    void aDeactivatedAccountTakesItsKeysWithIt() throws Exception {
        String ownerName = "key-owner-" + System.nanoTime();
        String key = issue(tokenFor(ownerName, Role.ADMIN, false), Map.of("name", "owned", "scopes", List.of("read")));
        mvc.perform(authenticated(get("/api/v1/issues"), key)).andExpect(status().isOk());

        UserEntity owner = users.findByUsername(ownerName).orElseThrow();
        owner.setIsActive(false);
        users.save(owner);

        mvc.perform(authenticated(get("/api/v1/issues"), key)).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("a restriction to a target that does not exist is refused, as is an oversized name")
    void issuanceValidatesItsInput() throws Exception {
        mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "ghost", "target_kind", "repository", "target_id", Long.MAX_VALUE))))
                .andExpect(status().isBadRequest());
        mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "x".repeat(101)))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("the agent scope is not issued from the keys screen")
    void theAgentScopeIsRefused() throws Exception {
        mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "sneaky", "scopes", List.of("agent")))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("an agent's key is kept on the agent routes")
    void anAgentKeyIsConfined() throws Exception {
        // It passed @RequiresAccount — authenticated is all that marker checks — and reached the
        // account routes with an empty visibility.
        String created = mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "confined-" + System.nanoTime()))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String agentKey = json.readTree(created).get("secret").asText();

        mvc.perform(authenticated(get("/api/v1/repositories"), agentKey))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.detail").value(Matchers.containsString("does not accept an agent key")));
    }
}
