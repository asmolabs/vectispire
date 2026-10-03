package com.asmolabs.vectispire.common.domain.forges;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.forges.ForgeConnectionRefusal.Reason;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("a forge connection's token, judged by what the forge reports")
class ForgeCredentialTest {

    private static Reason reasonOf(Runnable judged) {
        try {
            judged.run();
        } catch (ForgeConnectionRefusal refused) {
            return refused.reason();
        }
        throw new AssertionError("accepted");
    }

    @Test
    @DisplayName("GitLab: the read scopes are accepted, read_api required, and the token never writes")
    void gitlabReadScopes() {
        ForgeCredential credential = ForgeCredential.gitlab(List.of("read_user", " READ_API", "read_repository"), true);

        assertThat(credential.kind()).isEqualTo(ForgeCredential.Kind.GITLAB_BOT);
        assertThat(credential.scopes()).contains(List.of("read_api", "read_repository", "read_user"));
        assertThat(credential.canWrite()).contains(false);
        assertThat(reasonOf(() -> ForgeCredential.gitlab(List.of("read_repository"), true))).isEqualTo(Reason.SCOPE_MISSING);
    }

    @ParameterizedTest(name = "GitLab: {0} is refused")
    @ValueSource(strings = {"api", "write_repository", "sudo", "admin_mode", "create_runner", "k8s_proxy",
        "self_rotate", "a_scope_gitlab_adds_next_year"})
    void gitlabRefusesAnythingOutsideTheAllowList(String scope) {
        assertThat(reasonOf(() -> ForgeCredential.gitlab(List.of("read_api", scope), true)))
                .isEqualTo(Reason.SCOPE_REFUSED);
    }

    @Test
    @DisplayName("GitHub: a fine-grained token's permissions are unknown, not read-only")
    void fineGrainedIsUnknown() {
        ForgeCredential credential = ForgeCredential.github(ForgeEdition.GITHUB_COM, Optional.empty());

        assertThat(credential.kind()).isEqualTo(ForgeCredential.Kind.GITHUB_FINE_GRAINED);
        assertThat(credential.scopes()).isEmpty();
        assertThat(credential.canWrite()).isEmpty();
    }

    @Test
    @DisplayName("GitHub: a classic token is refused on the clouds, even with no scope at all")
    void classicRefusedOnTheClouds() {
        for (ForgeEdition cloud : List.of(ForgeEdition.GITHUB_COM, ForgeEdition.GITHUB_DATA_RESIDENCY)) {
            assertThat(reasonOf(() -> ForgeCredential.github(cloud, Optional.of("")))).isEqualTo(Reason.SCOPE_REFUSED);
        }
    }

    @Test
    @DisplayName("GitHub Enterprise Server: a classic token is accepted, flagged when repo or public_repo can write")
    void classicOnEnterpriseServer() {
        ForgeCredential writes = ForgeCredential.github(ForgeEdition.GITHUB_ENTERPRISE_SERVER, Optional.of("repo, read:org"));
        assertThat(writes.kind()).isEqualTo(ForgeCredential.Kind.GITHUB_CLASSIC);
        assertThat(writes.canWrite()).contains(true);

        assertThat(ForgeCredential.github(ForgeEdition.GITHUB_ENTERPRISE_SERVER, Optional.of("public_repo")).canWrite())
                .contains(true);
        ForgeCredential reads = ForgeCredential.github(ForgeEdition.GITHUB_ENTERPRISE_SERVER, Optional.of("read:org"));
        assertThat(reads.canWrite()).contains(false);
        assertThat(reads.scopes()).contains(List.of("read:org"));
    }

    @ParameterizedTest(name = "GitHub Enterprise Server: {0} is refused")
    @ValueSource(strings = {"admin:org", "delete_repo", "workflow", "write:packages", "site_admin", "admin:enterprise"})
    void classicRefusesAdministrationScopes(String scope) {
        assertThatThrownBy(() -> ForgeCredential.github(ForgeEdition.GITHUB_ENTERPRISE_SERVER, Optional.of("repo, " + scope)))
                .isInstanceOf(ForgeConnectionRefusal.class)
                .hasMessageContaining(scope);
    }

    @Test
    @DisplayName("only a blocked destination and a refused scope are security events")
    void whatIsSignalled() {
        assertThat(java.util.Arrays.stream(Reason.values()).filter(Reason::signalled))
                .containsExactlyInAnyOrder(Reason.DESTINATION_BLOCKED, Reason.SCOPE_REFUSED);
    }
}
