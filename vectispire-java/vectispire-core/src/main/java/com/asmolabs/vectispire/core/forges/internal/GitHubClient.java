package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.ForgeConnectionRefusal;
import com.asmolabs.vectispire.common.domain.forges.ForgeConnectionRefusal.Reason;
import com.asmolabs.vectispire.common.domain.forges.ForgeCredential;
import com.asmolabs.vectispire.common.domain.forges.ForgeEdition;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.forges.ForgeVersion;
import com.asmolabs.vectispire.common.domain.forges.TokenExpiry;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * GitHub's REST API — github.com, the data-residency cloud and Enterprise Server (decision 0037 §1).
 *
 * <p><b>The probe is one request</b>, {@code GET /users/{owner}}, and most of what it learns is in the
 * headers: {@code X-OAuth-Scopes} for a classic token (absent for a fine-grained one, whose permissions
 * GitHub does not report), {@code github-authentication-token-expiration}, and on Enterprise Server
 * {@code X-GitHub-Enterprise-Version}. GitHub answers 401 to a bad token even on a public route, so the
 * owner's lookup is also the token's check — and a 404 says the owner does not exist or is hidden from
 * this token, which a discovery would otherwise find out after its first page.
 */
@Component
class GitHubClient implements ForgeClient {

    /** The REST version the adapters are written against; GitHub keeps a version stable for two years. */
    static final String API_VERSION = "2022-11-28";

    private final OutboundJson outbound;

    GitHubClient(OutboundJson outbound) {
        this.outbound = outbound;
    }

    @Override
    public ForgeKind kind() {
        return ForgeKind.GITHUB;
    }

    @Override
    public Probe probe(Target target, String token) {
        ForgeEdition edition = target.address().edition();
        String owner = ForgePath.segment(target.owner()).orElseThrow(() -> new ForgeConnectionRefusal(
                Reason.OWNER_NOT_FOUND, "GitHub names no organisation or user \"" + target.owner() + "\"."));
        OutboundJson.Answer answer = outbound.answer(
                target.address().apiRoot() + "/users/" + owner,
                target.policy(),
                edition.label() + " at " + target.address().baseUrl(),
                Map.of("Authorization", "Bearer " + token, "X-GitHub-Api-Version", API_VERSION),
                target.trust());
        switch (answer.status()) {
            case 200 -> {
                // Read below.
            }
            case 401 -> throw new ForgeConnectionRefusal(Reason.TOKEN_REJECTED,
                    "GitHub rejected this token (HTTP 401): it is wrong, expired or revoked.");
            case 404 -> throw new ForgeConnectionRefusal(Reason.OWNER_NOT_FOUND, "GitHub knows no organisation or user \""
                    + target.owner() + "\" visible with this token.");
            // 403 is a rate limit, an organisation's SSO not yet authorised for the token, or an IP allow-list.
            default -> throw new ForgeConnectionRefusal(Reason.UNREACHABLE, "GitHub answered HTTP " + answer.status()
                    + answer.header("x-github-sso").map(sso -> " — authorise the token for the organisation's single "
                            + "sign-on first").orElse("") + ".");
        }

        // The scopes first: a token broader than a connection may hold is the security event, whatever
        // else is wrong with the server.
        ForgeCredential credential = ForgeCredential.github(edition, answer.header("x-oauth-scopes"));
        Optional<String> version = answer.header("x-github-enterprise-version").map(String::trim);
        if (edition == ForgeEdition.GITHUB_ENTERPRISE_SERVER
                && version.flatMap(found -> ForgeVersion.tooOld(edition, found)).orElse(false)) {
            throw new ForgeConnectionRefusal(Reason.VERSION_UNSUPPORTED, "This GitHub Enterprise Server is version "
                    + version.get() + "; " + ForgeVersion.GHES_MINIMUM_MAJOR + "." + ForgeVersion.GHES_MINIMUM_MINOR
                    + " or later is required.");
        }
        return new Probe(credential, answer.header("github-authentication-token-expiration").flatMap(TokenExpiry::ofGithubHeader),
                edition == ForgeEdition.GITHUB_ENTERPRISE_SERVER ? version : Optional.empty());
    }
}
