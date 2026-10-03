package com.asmolabs.vectispire.core.forges.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.forges.ForgeAddress;
import com.asmolabs.vectispire.common.domain.forges.ForgeConnectionRefusal;
import com.asmolabs.vectispire.common.domain.forges.ForgeConnectionRefusal.Reason;
import com.asmolabs.vectispire.common.domain.forges.ForgeCredential;
import com.asmolabs.vectispire.common.domain.forges.ForgeEdition;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;

/**
 * The probe of a forge connection (decision 0037 §2), against a forge that answers over HTTPS from loopback
 * with a private CA — the real door ({@code OutboundJson}, the guard, the pin), not a mock of it: what is
 * pinned here is what reached the wire, the headers the forge's answer carried, and which request was
 * never sent.
 */
@DisplayName("probing a forge connection's token")
class ForgeProbesTest {

    private static final String TOKEN = "glpat-Probe0000000000000000"; // gitleaks:allow
    private static final String GITHUB_TOKEN = "github_pat_11PROBE0000000000000000_probe"; // gitleaks:allow

    private ForgeStub forge;
    private ForgeProbes probes;
    private PinnedCa ca;

    @BeforeEach
    void start() throws Exception {
        forge = ForgeStub.start();
        OutboundJson outbound = new OutboundJson(new PinnedHttpSender(), new OutboundUrlGuard(), new ObjectMapper());
        probes = new ForgeProbes(List.of(new GitLabClient(outbound), new GitHubClient(outbound)));
        ca = PinnedCa.parse(forge.caPem, Instant.now(), new PinnedCa.Subject("The forge's CA", "the forge"));
    }

    @AfterEach
    void stop() {
        forge.close();
    }

    private ForgeClient.Target gitlab(String base) {
        return new ForgeClient.Target(ForgeAddress.of(ForgeKind.GITLAB, base), null, OutboundPolicy.INTERNAL_ALLOWED,
                Optional.of(ca));
    }

    private static Reason refusal(ThrowingCallable call) {
        Throwable thrown = org.assertj.core.api.Assertions.catchThrowable(call);
        assertThat(thrown).isInstanceOf(ForgeConnectionRefusal.class);
        return ((ForgeConnectionRefusal) thrown).reason();
    }

    @Nested
    @DisplayName("GitLab self-managed, on the internal network, behind a private CA")
    class GitLab {

        @Test
        @DisplayName("a group access token with read_api is accepted: its scopes, expiry, version and bot are read")
        void aReadApiGroupTokenIsAccepted() {
            forge.gitlab("16.11.2-ee", "[\"read_api\"]", true);

            ForgeClient.Probe probe = probes.probe(gitlab(forge.baseUrl()), TOKEN);

            assertThat(probe.credential().kind()).isEqualTo(ForgeCredential.Kind.GITLAB_BOT);
            assertThat(probe.credential().scopes()).contains(List.of("read_api"));
            assertThat(probe.credential().canWrite()).contains(false);
            assertThat(probe.expiresAt()).contains(Instant.parse("2027-01-31T00:00:00Z"));
            assertThat(probe.version()).contains("16.11.2-ee");
            assertThat(forge.seen).extracting(ForgeStub.Seen::path).containsExactly(
                    "/api/v4/personal_access_tokens/self", "/api/v4/version", "/api/v4/user");
            assertThat(forge.seen).allSatisfy(seen -> {
                assertThat(seen.method()).isEqualTo("GET");
                assertThat(seen.headers()).containsEntry("private-token", TOKEN);
            });
        }

        @Test
        @DisplayName("a personal access token is accepted and said to be one")
        void aPersonalTokenIsSaidToBeOne() {
            forge.gitlab("17.4.0", "[\"read_api\",\"read_user\"]", false);

            assertThat(probes.probe(gitlab(forge.baseUrl()), TOKEN).credential().kind())
                    .isEqualTo(ForgeCredential.Kind.GITLAB_PERSONAL);
        }

        @Test
        @DisplayName("the API is found under a relative URL root")
        void aPathPrefixIsKept() {
            forge.route("/gitlab/api/v4/personal_access_tokens/self",
                    Reply.json("{\"active\":true,\"scopes\":[\"read_api\"],\"expires_at\":null}"));
            forge.route("/gitlab/api/v4/version", Reply.json("{\"version\":\"16.0.0\"}"));
            forge.route("/gitlab/api/v4/user", Reply.json("{\"bot\":true}"));

            ForgeClient.Probe probe = probes.probe(gitlab(forge.baseUrl() + "/gitlab/"), TOKEN);

            assertThat(probe.expiresAt()).isEmpty();
            assertThat(forge.seen).extracting(ForgeStub.Seen::path).first().isEqualTo(
                    "/gitlab/api/v4/personal_access_tokens/self");
        }

        @Test
        @DisplayName("a token holding api is refused at the first answer, signalled, and presented nowhere else")
        void aWriteScopeIsRefused() {
            forge.gitlab("16.11.2", "[\"read_api\",\"api\"]", true);

            assertThat(refusal(() -> probes.probe(gitlab(forge.baseUrl()), TOKEN))).isEqualTo(Reason.SCOPE_REFUSED);
            assertThat(Reason.SCOPE_REFUSED.signalled()).isTrue();
            assertThat(forge.seen).hasSize(1);
        }

        @Test
        @DisplayName("a token without read_api is refused, and that is not a security event")
        void readApiIsRequired() {
            forge.gitlab("16.11.2", "[\"read_repository\"]", true);

            assertThat(refusal(() -> probes.probe(gitlab(forge.baseUrl()), TOKEN))).isEqualTo(Reason.SCOPE_MISSING);
            assertThat(Reason.SCOPE_MISSING.signalled()).isFalse();
        }

        @Test
        @DisplayName("a token GitLab rejects is refused as rejected")
        void aRejectedTokenIsRefused() {
            forge.route("/api/v4/personal_access_tokens/self", Reply.status(401));

            assertThat(refusal(() -> probes.probe(gitlab(forge.baseUrl()), TOKEN))).isEqualTo(Reason.TOKEN_REJECTED);
            assertThat(Reason.TOKEN_REJECTED.signalled()).isFalse();
        }

        @Test
        @DisplayName("a revoked token is refused even when GitLab still describes it")
        void aRevokedTokenIsRefused() {
            forge.gitlab("16.11.2", "[\"read_api\"]", true);
            forge.route("/api/v4/personal_access_tokens/self",
                    Reply.json("{\"active\":false,\"revoked\":true,\"scopes\":[\"read_api\"]}"));

            assertThat(refusal(() -> probes.probe(gitlab(forge.baseUrl()), TOKEN))).isEqualTo(Reason.TOKEN_REJECTED);
        }

        @Test
        @DisplayName("a GitLab older than 16 is refused with the version it reported")
        void anOldGitLabIsRefused() {
            forge.gitlab("15.11.13-ee", "[\"read_api\"]", true);

            assertThatThrownBy(() -> probes.probe(gitlab(forge.baseUrl()), TOKEN))
                    .isInstanceOf(ForgeConnectionRefusal.class)
                    .hasMessageContaining("15.11.13-ee")
                    .satisfies(refused -> assertThat(((ForgeConnectionRefusal) refused).reason())
                            .isEqualTo(Reason.VERSION_UNSUPPORTED));
        }

        @Test
        @DisplayName("without the pinned CA the private certificate is not trusted: nothing is skipped")
        void thePrivateCaMustBePinned() {
            forge.gitlab("16.11.2", "[\"read_api\"]", true);
            ForgeClient.Target unpinned = new ForgeClient.Target(ForgeAddress.of(ForgeKind.GITLAB, forge.baseUrl()), null,
                    OutboundPolicy.INTERNAL_ALLOWED, Optional.empty());

            assertThat(refusal(() -> probes.probe(unpinned, TOKEN))).isEqualTo(Reason.UNREACHABLE);
            assertThat(forge.seen).isEmpty();
        }

        @Test
        @DisplayName("an internal address under PUBLIC_ONLY is blocked before any byte is sent, and signalled")
        void anInternalAddressIsBlockedUnlessStated() {
            forge.gitlab("16.11.2", "[\"read_api\"]", true);
            ForgeClient.Target publicOnly = new ForgeClient.Target(ForgeAddress.of(ForgeKind.GITLAB, forge.baseUrl()),
                    null, OutboundPolicy.PUBLIC_ONLY, Optional.of(ca));

            assertThatThrownBy(() -> probes.probe(publicOnly, TOKEN))
                    .isInstanceOf(ForgeConnectionRefusal.class)
                    .hasMessageContaining("internal network")
                    .satisfies(refused -> assertThat(((ForgeConnectionRefusal) refused).reason())
                            .isEqualTo(Reason.DESTINATION_BLOCKED));
            assertThat(Reason.DESTINATION_BLOCKED.signalled()).isTrue();
            assertThat(forge.seen).isEmpty();
        }
    }

    @Nested
    @DisplayName("GitHub")
    class GitHub {

        private ForgeClient.Target enterpriseServer() {
            return new ForgeClient.Target(ForgeAddress.of(ForgeKind.GITHUB, forge.baseUrl()), "acme",
                    OutboundPolicy.INTERNAL_ALLOWED, Optional.of(ca));
        }

        /** github.com's rules, at the stub's address: the edition decides, not the host. */
        private ForgeClient.Target cloud() {
            return new ForgeClient.Target(new ForgeAddress(ForgeEdition.GITHUB_COM, forge.baseUrl(),
                    forge.baseUrl() + "/api/v3"), "acme", OutboundPolicy.INTERNAL_ALLOWED, Optional.of(ca));
        }

        private void owner(Reply reply) {
            forge.route("/api/v3/users/acme", reply);
        }

        @Test
        @DisplayName("on Enterprise Server a classic token with repo is accepted, flagged as able to write")
        void aClassicTokenOnEnterpriseServerIsFlagged() {
            owner(Reply.json("{\"login\":\"acme\",\"type\":\"Organization\"}")
                    .with("X-OAuth-Scopes", "repo, read:org")
                    .with("X-GitHub-Enterprise-Version", "3.14.2"));

            ForgeClient.Probe probe = probes.probe(enterpriseServer(), GITHUB_TOKEN);

            assertThat(probe.credential().kind()).isEqualTo(ForgeCredential.Kind.GITHUB_CLASSIC);
            assertThat(probe.credential().scopes()).contains(List.of("read:org", "repo"));
            assertThat(probe.credential().canWrite()).contains(true);
            assertThat(probe.version()).contains("3.14.2");
            assertThat(forge.seen).singleElement().satisfies(seen -> {
                assertThat(seen.path()).isEqualTo("/api/v3/users/acme");
                assertThat(seen.headers()).containsEntry("authorization", "Bearer " + GITHUB_TOKEN)
                        .containsEntry("x-github-api-version", "2022-11-28");
            });
        }

        @Test
        @DisplayName("on Enterprise Server a classic token holding an administration scope is refused")
        void anAdministrationScopeIsRefused() {
            owner(Reply.json("{\"login\":\"acme\"}").with("X-OAuth-Scopes", "repo, admin:org")
                    .with("X-GitHub-Enterprise-Version", "3.14.2"));

            assertThat(refusal(() -> probes.probe(enterpriseServer(), GITHUB_TOKEN))).isEqualTo(Reason.SCOPE_REFUSED);
        }

        @Test
        @DisplayName("an Enterprise Server older than 3.12 is refused")
        void anOldEnterpriseServerIsRefused() {
            owner(Reply.json("{\"login\":\"acme\"}").with("X-GitHub-Enterprise-Version", "3.11.9"));

            assertThat(refusal(() -> probes.probe(enterpriseServer(), GITHUB_TOKEN)))
                    .isEqualTo(Reason.VERSION_UNSUPPORTED);
        }

        @Test
        @DisplayName("on github.com a classic token is refused and signalled: a fine-grained one is always possible")
        void aClassicTokenOnTheCloudIsRefused() {
            owner(Reply.json("{\"login\":\"acme\"}").with("X-OAuth-Scopes", "read:org"));

            assertThat(refusal(() -> probes.probe(cloud(), GITHUB_TOKEN))).isEqualTo(Reason.SCOPE_REFUSED);
        }

        @Test
        @DisplayName("a fine-grained token is accepted with its permissions unknown, never stated as read-only")
        void aFineGrainedTokenIsUnknownNotReadOnly() {
            owner(Reply.json("{\"login\":\"acme\"}")
                    .with("github-authentication-token-expiration", "2026-12-01 10:00:00 UTC"));

            ForgeClient.Probe probe = probes.probe(cloud(), GITHUB_TOKEN);

            assertThat(probe.credential().kind()).isEqualTo(ForgeCredential.Kind.GITHUB_FINE_GRAINED);
            assertThat(probe.credential().scopes()).isEmpty();
            assertThat(probe.credential().canWrite()).isEmpty();
            assertThat(probe.expiresAt()).contains(Instant.parse("2026-12-01T10:00:00Z"));
            assertThat(probe.version()).isEmpty();
        }

        @Test
        @DisplayName("a token GitHub rejects, and an owner it does not know, are refused as such")
        void rejectedTokenAndUnknownOwner() {
            owner(Reply.status(401));
            assertThat(refusal(() -> probes.probe(cloud(), GITHUB_TOKEN))).isEqualTo(Reason.TOKEN_REJECTED);

            owner(Reply.status(404));
            assertThat(refusal(() -> probes.probe(cloud(), GITHUB_TOKEN))).isEqualTo(Reason.OWNER_NOT_FOUND);
        }
    }
}
