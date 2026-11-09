package com.asmolabs.vectispire.common.domain.forges;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * What a forge said about a connection's token, judged against the scopes a connection may hold
 * (decision 0037 §2).
 *
 * <p><b>An allow-list, not a deny-list.</b> A scope the forge reports and this class does not name is
 * refused — so a scope a forge adds next year is refused until somebody has read what it grants and
 * written it here, rather than accepted because nobody had thought to forbid it.
 *
 * <p><b>Unknown is not "no".</b> GitHub does not report a fine-grained token's permissions through its
 * API: {@link #scopes} is then empty and {@link #canWrite} empty too — not {@code false}, which would
 * state something nobody checked. The administration guide tells the administrator to grant
 * <em>Metadata: read</em> only, which is a sentence, not a check, and is written as one.
 *
 * @param scopes the scopes as the forge reported them, sorted; empty when it reports none
 * @param canWrite whether the token can write to a repository; empty when the forge does not say
 */
public record ForgeCredential(Kind kind, Optional<List<String>> scopes, Optional<Boolean> canWrite) {

    /** What kind of credential the forge's answers identify. */
    public enum Kind {
        /** A fine-grained personal access token: its permissions are not readable. */
        GITHUB_FINE_GRAINED,
        /** A classic personal access token: its scopes are reported, and {@code repo} writes. */
        GITHUB_CLASSIC,
        /** A group or project access token: a bot member that outlives the person who made it — preferred. */
        GITLAB_BOT,
        /** A personal access token: it acts as, and dies with, the account that made it. */
        GITLAB_PERSONAL;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** What a GitLab connection must hold: listing groups and projects is the API's, read-only. */
    public static final String GITLAB_REQUIRED = "read_api";

    /**
     * The GitLab scopes a connection may hold: the read scopes. {@code api}, {@code write_repository},
     * {@code sudo}, {@code admin_mode}, the runner and Kubernetes scopes, and anything GitLab adds later,
     * are refused.
     */
    public static final Set<String> GITLAB_ALLOWED = Set.of("read_api", "read_repository", "read_registry", "read_user");

    /**
     * The classic GitHub scopes a connection on Enterprise Server may hold. {@code repo} is the only one
     * that lists private repositories and it writes to every one of them, {@code public_repo} writes to
     * the public ones: both accepted there, and flagged. Administration scopes, {@code delete_repo},
     * {@code workflow} and the package scopes are refused.
     */
    public static final Set<String> GITHUB_CLASSIC_ALLOWED = Set.of("repo", "public_repo", "read:org", "read:user", "user:email");

    private static final Set<String> GITHUB_CLASSIC_WRITING = Set.of("repo", "public_repo");

    public ForgeCredential {
        scopes = scopes.map(List::copyOf);
    }

    /**
     * Judges a GitLab token from {@code GET /personal_access_tokens/self} and {@code GET /user}.
     *
     * @param scopes the token's scopes as GitLab lists them
     * @param bot whether the token's user is a bot — what a group or project access token acts as
     * @throws ForgeConnectionRefusal a scope outside {@link #GITLAB_ALLOWED} ({@code SCOPE_REFUSED}),
     *     {@code read_api} absent ({@code SCOPE_MISSING})
     */
    public static ForgeCredential gitlab(Collection<String> scopes, boolean bot) {
        Set<String> held = normalised(scopes);
        Set<String> refused = new TreeSet<>(held);
        refused.removeAll(GITLAB_ALLOWED);
        if (!refused.isEmpty()) {
            throw new ForgeConnectionRefusal(ForgeConnectionRefusal.Reason.SCOPE_REFUSED,
                    "GitLab reports this token with the scope(s) " + String.join(", ", refused) + ", which a "
                            + "connection may not hold: it lists repositories and needs read_api alone. Create a "
                            + "token with read_api only — a group access token, role Reporter, is preferred.");
        }
        if (!held.contains(GITLAB_REQUIRED)) {
            throw new ForgeConnectionRefusal(ForgeConnectionRefusal.Reason.SCOPE_MISSING,
                    "This token lacks the read_api scope, without which GitLab lists no group and no project.");
        }
        return new ForgeCredential(bot ? Kind.GITLAB_BOT : Kind.GITLAB_PERSONAL,
                Optional.of(List.copyOf(held)), Optional.of(false));
    }

    /**
     * Judges a GitHub token from the {@code X-OAuth-Scopes} header of an authenticated answer.
     *
     * <p>GitHub sends that header for a classic token — empty when it holds no scope — and not at all
     * for a fine-grained one. A classic token is accepted on Enterprise Server alone, where fine-grained
     * tokens may not be offered (the owner's answer 2): on github.com and the data-residency cloud the
     * narrowest classic scope that lists private repositories writes to all of them, and a fine-grained
     * token with <em>Metadata: read</em> is always available instead.
     *
     * @param oauthScopes the header's value; empty when the answer did not carry it
     * @throws ForgeConnectionRefusal {@code SCOPE_REFUSED} for a classic token on a cloud edition, or a
     *     classic scope outside {@link #GITHUB_CLASSIC_ALLOWED}
     */
    public static ForgeCredential github(ForgeEdition edition, Optional<String> oauthScopes) {
        if (oauthScopes.isEmpty()) {
            return new ForgeCredential(Kind.GITHUB_FINE_GRAINED, Optional.empty(), Optional.empty());
        }
        Set<String> held = normalised(Arrays.asList(oauthScopes.get().split(",")));
        if (edition.cloud()) {
            throw new ForgeConnectionRefusal(ForgeConnectionRefusal.Reason.SCOPE_REFUSED,
                    "This is a classic token, which " + edition.label() + " does not accept for a connection: the "
                            + "only classic scope that lists private repositories, repo, can also write to every one "
                            + "of them. Create a fine-grained token for the owner with the permission Metadata: read, "
                            + "and nothing else.");
        }
        Set<String> refused = new TreeSet<>(held);
        refused.removeAll(GITHUB_CLASSIC_ALLOWED);
        if (!refused.isEmpty()) {
            throw new ForgeConnectionRefusal(ForgeConnectionRefusal.Reason.SCOPE_REFUSED,
                    "GitHub reports this classic token with the scope(s) " + String.join(", ", refused) + ", which "
                            + "a connection may not hold. Use a token with repo (or public_repo) and read:org only.");
        }
        boolean writes = held.stream().anyMatch(GITHUB_CLASSIC_WRITING::contains);
        return new ForgeCredential(Kind.GITHUB_CLASSIC, Optional.of(List.copyOf(held)), Optional.of(writes));
    }

    private static Set<String> normalised(Collection<String> scopes) {
        Set<String> held = new TreeSet<>();
        for (String scope : scopes) {
            String value = scope == null ? "" : scope.trim().toLowerCase(Locale.ROOT);
            if (!value.isEmpty()) {
                held.add(value);
            }
        }
        return held;
    }
}
