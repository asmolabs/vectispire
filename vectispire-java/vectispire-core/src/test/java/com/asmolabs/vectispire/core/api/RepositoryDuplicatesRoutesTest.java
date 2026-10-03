package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.targets.RepositoryAdministrationService;
import com.asmolabs.vectispire.core.targets.RepositoryAdministrationService.Changes;
import com.asmolabs.vectispire.core.targets.RepositoryAdministrationService.TargetAlreadyRegisteredException;
import com.asmolabs.vectispire.core.targets.RepositoryIdentityService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * A repository target filed twice is refused, at creation and at a change of URL, branch or sub-path —
 * decision 0037, §4 — and the twins filed before the rule are listed, never deleted.
 */
@DisplayName("a repository target filed twice")
class RepositoryDuplicatesRoutesTest extends ApiTestBase {

    private static final String TYPE = "urn:vectispire:problem:target-already-registered";

    private static final RequestActor ACTOR = new RequestActor("duplicates-test", null, null);

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private RepositoryAdministrationService inventory;

    @Autowired
    private RepositoryIdentityService identities;

    @Test
    @DisplayName("is refused at creation whatever the spelling, the existing target named to an administrator")
    void theSameRepositorySpelledAnotherWay() throws Exception {
        String admin = asAdmin();
        long api = create(admin, "{\"url\":\"https://gitlab.example.org/Team/API.git\",\"branch\":\"main\",\"name\":\"Payments API\"}");

        for (String url : new String[] {
            "git@gitlab.example.org:team/api.git",
            "ssh://git@gitlab.example.org:2222/team/api",
            "https://gitlab.example.org/team/api/"
        }) {
            MvcResult refused = mvc.perform(authenticated(post("/api/v1/repositories"), admin)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"url\":\"" + url + "\",\"branch\":\"main\"}"))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.type").value(TYPE))
                    .andExpect(jsonPath("$.existingRepositoryId").value(api))
                    .andReturn();
            assertThat(detailOf(refused)).as(url)
                    .contains("\"Payments API\"")
                    .contains("(id " + api + ")")
                    .contains("on branch main, at its root");
        }
        assertThat(repositories.count()).as("nothing was filed by the refused requests").isEqualTo(1);

        // Refused before the write, not by the index: a failed insert spends an identity value on MySQL and
        // PostgreSQL alike, and logs the driver's error for an ordinary mistake.
        long next = create(admin, "{\"url\":\"https://gitlab.example.org/team/next.git\",\"branch\":\"main\"}");
        assertThat(next).as("no insert was attempted for the three refusals").isEqualTo(api + 1);
    }

    @Test
    @DisplayName("but another directory of a monorepo, or another branch, is another target")
    void subPathsAndBranchesAreTargetsOfTheirOwn() throws Exception {
        String admin = asAdmin();
        create(admin, "{\"url\":\"https://gitlab.example.org/team/mono.git\",\"branch\":\"main\"}");
        long apiDir = create(admin,
                "{\"url\":\"https://gitlab.example.org/team/mono.git\",\"branch\":\"main\",\"subPath\":\"services/api\"}");
        create(admin, "{\"url\":\"git@gitlab.example.org:team/mono.git\",\"branch\":\"main\",\"subPath\":\"services/billing\"}");
        create(admin, "{\"url\":\"https://gitlab.example.org/team/mono.git\",\"branch\":\"release/2.x\"}");

        MvcResult refused = mvc.perform(authenticated(post("/api/v1/repositories"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\"git@gitlab.example.org:team/mono\",\"branch\":\"main\",\"subPath\":\"services/api/\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(TYPE))
                .andExpect(jsonPath("$.existingRepositoryId").value(apiDir))
                .andReturn();
        assertThat(detailOf(refused)).contains("under services/api");
        assertThat(repositories.count()).isEqualTo(4);
    }

    @Test
    @DisplayName("is refused when an edit makes a target another's twin, and an unrelated edit is not")
    void anEditIsRefusedLikeACreation() throws Exception {
        String admin = asAdmin();
        long first = create(admin, "{\"url\":\"https://gitlab.example.org/team/one.git\",\"branch\":\"main\"}");
        long second = create(admin, "{\"url\":\"https://gitlab.example.org/team/two.git\",\"branch\":\"main\"}");

        mvc.perform(authenticated(patch("/api/v1/repositories/" + second), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\"git@gitlab.example.org:team/one.git\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(TYPE))
                .andExpect(jsonPath("$.existingRepositoryId").value(first));
        assertThat(repositories.findById(second).orElseThrow().getUrl()).endsWith("/two.git");

        // Saving the form untouched compares the target with itself, which is no twin.
        mvc.perform(authenticated(patch("/api/v1/repositories/" + first), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\"git@gitlab.example.org:team/one.git\",\"name\":\"One\"}"))
                .andExpect(status().isOk());

        // The branch moves it to another target, and back onto the first one's is refused.
        mvc.perform(authenticated(patch("/api/v1/repositories/" + second), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\"https://gitlab.example.org/team/one\",\"branch\":\"develop\"}"))
                .andExpect(status().isOk());
        mvc.perform(authenticated(patch("/api/v1/repositories/" + second), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"branch\":\"main\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.existingRepositoryId").value(first));
    }

    @Test
    @DisplayName("filed before the rule: both kept, listed for a merge, the oldest keyed, the younger still editable")
    void twinsFiledBeforeTheRule() throws Exception {
        String admin = asAdmin();
        // Rows as V73 finds them: no identity, no guard.
        long older = legacyRow("https://gitlab.example.org/team/legacy.git");
        long younger = legacyRow("git@gitlab.example.org:Team/Legacy");
        legacyRow("https://gitlab.example.org/team/alone.git");

        mvc.perform(authenticated(get("/api/v1/repositories/duplicates"), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].repository").value("gitlab.example.org/team/legacy"))
                .andExpect(jsonPath("$[0].branch").value("main"))
                .andExpect(jsonPath("$[0].subPath").value(""))
                .andExpect(jsonPath("$[0].targets.length()").value(2))
                .andExpect(jsonPath("$[0].targets[0].id").value(older))
                .andExpect(jsonPath("$[0].targets[1].id").value(younger));

        RepositoryIdentityService.Keyed keyed = identities.keyUnkeyed();

        assertThat(keyed).isEqualTo(new RepositoryIdentityService.Keyed(2, 1));
        RepositoryEntity kept = repositories.findById(older).orElseThrow();
        RepositoryEntity twin = repositories.findById(younger).orElseThrow();
        assertThat(kept.getIdentityGuard()).as("the oldest holds the guard").isNotNull();
        assertThat(twin.getIdentityGuard()).as("its twin cannot, and keeps serving").isNull();
        assertThat(twin.getUrlIdentity()).as("but carries the identity discovery compares").isEqualTo("gitlab.example.org/team/legacy");
        assertThat(identities.keyUnkeyed()).as("a second turn finds nothing to do").isEqualTo(new RepositoryIdentityService.Keyed(0, 1));

        // Once keyed, a third filing is refused against the oldest.
        mvc.perform(authenticated(post("/api/v1/repositories"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\"https://gitlab.example.org/team/legacy\",\"branch\":\"main\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.existingRepositoryId").value(older));

        // The twin's settings stay editable: it is not the edit that made it a twin.
        mvc.perform(authenticated(patch("/api/v1/repositories/" + younger), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"legacy (to merge)\",\"tier\":\"TIER_1_MISSION_CRITICAL\"}"))
                .andExpect(status().isOk());
        assertThat(repositories.findById(younger).orElseThrow().getIdentityGuard()).isNull();
    }

    @Test
    @DisplayName("the list of duplicates is an administrator's")
    void theListIsAnAdministrators() throws Exception {
        mvc.perform(authenticated(get("/api/v1/repositories/duplicates"), asReader()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("refused to a caller who does not see the existing target without naming it")
    void aHiddenTwinIsNotNamed() throws Exception {
        long hidden = create(asAdmin(),
                "{\"url\":\"https://gitlab.example.org/secret/vault.git\",\"branch\":\"main\",\"name\":\"Vault\"}");
        long visible = create(asAdmin(), "{\"url\":\"https://gitlab.example.org/team/open.git\",\"branch\":\"main\"}");
        Visibility narrow = Visibility.only(Set.of(new ScanTarget.Repository(visible)));

        assertThatThrownBy(() -> inventory.create(
                        changes("git@gitlab.example.org:secret/vault.git"), narrow, ACTOR))
                .isInstanceOfSatisfying(TargetAlreadyRegisteredException.class, refused -> {
                    assertThat(refused.getMessage())
                            .isEqualTo("This repository is already registered, on this branch and sub-path.")
                            .doesNotContain(String.valueOf(hidden))
                            .doesNotContain("Vault");
                    assertThat(refused.members()).as("no id in the problem either").isEmpty();
                    assertThat(refused.conflictCause()).contains(TargetAlreadyRegisteredException.CAUSE);
                });
        assertThatThrownBy(() -> inventory.update(visible,
                        changes("https://gitlab.example.org/secret/vault"), narrow, ACTOR))
                .isInstanceOfSatisfying(ConflictException.class, refused -> assertThat(refused.members()).isEmpty());

        assertThatThrownBy(() -> inventory.create(changes("https://gitlab.example.org/team/open"), narrow, ACTOR))
                .as("a twin the caller sees is named")
                .isInstanceOfSatisfying(ConflictException.class,
                        refused -> assertThat(refused.members()).containsEntry("existingRepositoryId", visible));
    }

    private long create(String token, String body) throws Exception {
        MvcResult created = mvc.perform(authenticated(post("/api/v1/repositories"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode answer = json.readTree(created.getResponse().getContentAsString());
        return answer.get("id").asLong();
    }

    private long legacyRow(String url) {
        RepositoryEntity row = new RepositoryEntity();
        row.setUrl(url);
        row.setBranch("main");
        return repositories.save(row).getId();
    }

    private static Changes changes(String url) {
        return new Changes(url, "main", null, null, null, null, null, null, null);
    }
}
