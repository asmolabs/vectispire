package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.DiscoveredRepository;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryReason;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPager;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * GitHub's listing (decision 0037 §3, lot D4) — github.com, the data-residency cloud ({@code api.<sub>.ghe.com}) and
 * Enterprise Server ({@code /api/v3} under the web address) alike: the address's API root is the only difference.
 *
 * <p><b>Per owner, one organisation at a time.</b> GitHub has no membership listing across organisations as GitLab
 * has: an organisation's repositories are {@code GET /orgs/{org}/repos?type=all}, the user's own {@code GET
 * /user/repos?affiliation=owner}. Which owners depends on the token, read from {@code GET /user} at every run — a
 * token replaced since the last run is judged as it is now:
 * <ul>
 *   <li>a <b>fine-grained</b> token (no {@code X-OAuth-Scopes} header) is issued for exactly one resource owner, the
 *       connection's: that organisation, or the user's own repositories when the owner is the token's user. Asking
 *       it about another organisation would list that one's public repositories, which nobody asked for;</li>
 *   <li>a <b>classic</b> token — Enterprise Server only, flagged as able to write since D1 — sees every
 *       organisation its user belongs to: the connection's owner, then {@code GET /user/orgs}, then the user's own
 *       repositories.</li>
 * </ul>
 * The user's own repositories are a <b>personal namespace</b>: listed, flagged, offered unticked (answer 7).
 *
 * <p><b>A 403 on one organisation marks it unreadable, not the run failed</b> (§3) — single sign-on the token is not
 * authorised for ({@code X-GitHub-SSO: required}), an IP allow list, an organisation refusing this kind of token —
 * and a 404 the same: an organisation renamed, or hidden from the token, is not proof its repositories went. Its
 * repositories are not marked gone by the run. A 401 is the token's and fails the run. A 403 that is a rate limit
 * never reaches here: the pager waits it out, or ends the run partial.
 *
 * <p><b>What GitHub withholds without naming.</b> Single sign-on filters a list rather than refusing it: {@code GET
 * /user/orgs} answers 200 without the organisations the token is not authorised for, and says so only in {@code
 * X-GitHub-SSO: partial-results; organizations=…} — by id. And a classic token without {@code read:org} is refused
 * the list outright. Either way the run cannot know every organisation the token sees, so it says so ({@link
 * ForgeLister.Listing#namespacesIncomplete}) and marks nothing gone outside the namespaces it read.
 *
 * <p><b>The metadata is the listing's</b>: GitHub states every field in it — the language too, so no request per
 * repository — and states {@code fork} and {@code archived} always, so neither is unknown here. The size is in
 * kibibytes. An empty repository still names a default branch; its first scan says it is empty.
 */
@Component
class GitHubLister implements ForgeLister {

    static final String USER = "/user";

    static final String USER_ORGS = "/user/orgs?per_page=100";

    static final String USER_REPOS = "/user/repos?affiliation=owner&visibility=all&sort=full_name&per_page=100";

    @Override
    public ForgeKind kind() {
        return ForgeKind.GITHUB;
    }

    @Override
    public void list(Listing listing) {
        String api = listing.target().address().apiRoot();
        OutboundPager pager = listing.pager(Map.of("Authorization", "Bearer " + listing.token(),
                "X-GitHub-Api-Version", GitHubClient.API_VERSION));

        OutboundJson.Answer self = pager.get(api + USER);
        switch (self.status()) {
            case 200 -> {
                // Read below.
            }
            case 401 -> throw rejected();
            default -> throw new ForgeListingException(DiscoveryReason.FORGE_REFUSED, "GitHub refused to name the "
                    + "token's user (HTTP " + self.status() + "): the discovery cannot tell its own repositories from an "
                    + "organisation's.");
        }
        String login = self.body().map(user -> text(user, "login")).orElseThrow(() -> new ForgeListingException(
                DiscoveryReason.FORGE_UNAVAILABLE, "GitHub answered the token's user with no login."));
        boolean classic = self.header("x-oauth-scopes").isPresent();
        String owner = listing.target().owner();
        boolean ownerIsUser = owner == null || owner.equalsIgnoreCase(login);

        // By lower-case login: GitHub's logins are case-insensitive, and the owner is typed by a person.
        Map<String, String> organisations = new LinkedHashMap<>();
        if (!ownerIsUser) {
            organisations.put(owner.toLowerCase(Locale.ROOT), owner);
        }
        if (classic) {
            organisationsOf(pager, api, listing).forEach(org -> organisations.putIfAbsent(org.toLowerCase(Locale.ROOT), org));
        }
        for (String organisation : organisations.values()) {
            listing.namespace(organisation);
            walk(pager, api + "/orgs/" + URLEncoder.encode(organisation, StandardCharsets.UTF_8)
                    + "/repos?type=all&sort=full_name&per_page=100", organisation, false, listing);
        }
        if (classic || ownerIsUser) {
            listing.namespace(login);
            walk(pager, api + USER_REPOS, login, true, listing);
        }
    }

    /** The organisations a classic token sees; what GitHub withholds is said to the listing, not guessed at. */
    private static List<String> organisationsOf(OutboundPager pager, String api, Listing listing) {
        List<String> found = new ArrayList<>();
        Optional<String> url = Optional.of(api + USER_ORGS);
        while (url.isPresent()) {
            OutboundJson.Answer answer = pager.get(url.get());
            switch (answer.status()) {
                case 200 -> {
                    // Read below.
                }
                case 401 -> throw rejected();
                default -> {
                    listing.namespacesIncomplete("GitHub refused to list the organisations this token belongs to (HTTP "
                            + answer.status() + " — a classic token needs read:org for it): only the connection's owner "
                            + "and the user's own repositories were listed.");
                    return found;
                }
            }
            answer.header("x-github-sso").flatMap(GitHubLister::withheldOrganisations).ifPresent(ids ->
                    listing.namespacesIncomplete("GitHub left out " + ids.size() + (ids.size() == 1 ? " organisation"
                            : " organisations") + " (id " + String.join(", ", ids) + ") enforcing SAML single sign-on "
                            + "this token is not authorised for: authorise the token for each on GitHub, then discover "
                            + "again."));
            JsonNode page = answer.body().filter(JsonNode::isArray).orElseThrow(() -> new ForgeListingException(
                    DiscoveryReason.FORGE_UNAVAILABLE, "GitHub answered the list of organisations with no list."));
            page.forEach(org -> {
                String name = text(org, "login");
                if (name != null) {
                    found.add(name);
                }
            });
            url = pager.next(answer, url.get(), OutboundPager.NextPage.LINK);
        }
        return found;
    }

    /** Reads every page of one owner's repositories; a refusal on any page makes the owner unreadable. */
    private static void walk(OutboundPager pager, String first, String namespace, boolean personal, Listing listing) {
        Optional<String> url = Optional.of(first);
        while (url.isPresent()) {
            OutboundJson.Answer answer = pager.get(url.get());
            switch (answer.status()) {
                case 200 -> {
                    // Read below.
                }
                case 401 -> throw rejected();
                default -> {
                    listing.unreadable(namespace, refusal(answer, personal));
                    return;
                }
            }
            JsonNode page = answer.body().filter(JsonNode::isArray).orElseThrow(() -> new ForgeListingException(
                    DiscoveryReason.FORGE_UNAVAILABLE, "GitHub answered the repositories of " + namespace
                            + " with no list."));
            List<DiscoveredRepository> repositories = new ArrayList<>();
            page.forEach(repository -> repositories.add(repositoryOf(repository, namespace, personal)));
            listing.repositories(repositories);
            url = pager.next(answer, url.get(), OutboundPager.NextPage.LINK);
        }
    }

    /** Why GitHub would not list an owner, in words an administrator can act on. */
    static String refusal(OutboundJson.Answer answer, boolean personal) {
        if (answer.header("x-github-sso").filter(sso -> sso.trim().toLowerCase(Locale.ROOT).startsWith("required"))
                .isPresent()) {
            return "the organisation enforces SAML single sign-on and this token is not authorised for it (HTTP 403): "
                    + "authorise the token for the organisation on GitHub, then discover again.";
        }
        return switch (answer.status()) {
            case 403 -> "GitHub refused to list its repositories to this token (HTTP 403): an IP allow list, a policy "
                    + "refusing this kind of token, or a token not granted " + (personal ? "the user's repositories."
                            : "the organisation.");
            case 404 -> "GitHub shows no " + (personal ? "user" : "organisation") + " of that name to this token "
                    + "(HTTP 404): renamed, deleted, or a user rather than an organisation.";
            default -> "GitHub answered the listing with HTTP " + answer.status() + ".";
        };
    }

    /** The ids of the organisations {@code X-GitHub-SSO: partial-results; organizations=1,2} says were left out. */
    static Optional<List<String>> withheldOrganisations(String header) {
        String value = header.trim();
        if (!value.toLowerCase(Locale.ROOT).startsWith("partial-results")) {
            return Optional.empty();
        }
        List<String> ids = new ArrayList<>();
        for (String part : value.split(";")) {
            String pair = part.trim();
            if (pair.toLowerCase(Locale.ROOT).startsWith("organizations=")) {
                for (String id : pair.substring("organizations=".length()).split(",")) {
                    if (id.trim().matches("[0-9]{1,20}")) {
                        ids.add(id.trim());
                    }
                }
            }
        }
        return ids.isEmpty() ? Optional.of(List.of("unstated")) : Optional.of(List.copyOf(ids));
    }

    static DiscoveredRepository repositoryOf(JsonNode repository, String namespace, boolean personal) {
        String fullPath = orEmpty(text(repository, "full_name"));
        String owner = text(repository.path("owner"), "login");
        if (owner == null) {
            int slash = fullPath.indexOf('/');
            owner = slash < 0 ? namespace : fullPath.substring(0, slash);
        }
        JsonNode size = repository.path("size");
        return new DiscoveredRepository(
                repository.path("id").isIntegralNumber() ? repository.path("id").asText() : orEmpty(text(repository, "id")),
                fullPath,
                owner,
                personal,
                orEmpty(text(repository, "name")),
                text(repository, "default_branch"),
                flag(repository.path("archived")),
                flag(repository.path("fork")),
                visibility(repository),
                instant(text(repository, "pushed_at")),
                text(repository, "language"),
                size.isIntegralNumber() && size.asLong() <= Long.MAX_VALUE / 1024 ? size.asLong() * 1024 : null,
                text(repository, "clone_url"),
                text(repository, "ssh_url"),
                text(repository, "html_url"));
    }

    /**
     * {@code visibility} — public, private, or internal on Enterprise Server and Enterprise Cloud; read from {@code
     * private} only where the field is missing, which then cannot say internal.
     */
    private static String visibility(JsonNode repository) {
        String stated = text(repository, "visibility");
        if (stated != null) {
            return stated;
        }
        JsonNode hidden = repository.path("private");
        return hidden.isBoolean() ? (hidden.asBoolean() ? "private" : "public") : null;
    }

    private static Boolean flag(JsonNode value) {
        return value.isBoolean() ? value.asBoolean() : null;
    }

    private static ForgeListingException rejected() {
        return new ForgeListingException(DiscoveryReason.TOKEN_REJECTED,
                "GitHub rejected this token (HTTP 401): it is wrong, expired or revoked. Replace it on the connection.");
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isTextual()) {
            return value.asText().isBlank() ? null : value.asText();
        }
        return value.isNumber() ? value.asText() : null;
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }

    private static Instant instant(String value) {
        if (value == null) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value).toInstant();
        } catch (DateTimeParseException unreadable) {
            return null;
        }
    }
}
