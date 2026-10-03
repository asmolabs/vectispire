package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.DiscoveredRepository;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryReason;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPager;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import org.springframework.stereotype.Component;

/**
 * GitLab's listing (decision 0037 §3, lot D3): the groups the token belongs to, then its projects with their
 * metadata, then the language of the projects worth asking about.
 *
 * <p><b>{@code membership=true} and {@code min_access_level} are not optional.</b> On gitlab.com, without them,
 * {@code /projects} and {@code /groups} list every public project and group of the service — millions — and a
 * discovery would page through other people's repositories until its bound. Both listings carry {@code
 * min_access_level=10} (Guest), the projects' {@code membership=true} too, and the adapter's tests assert the
 * parameters, not just the result.
 *
 * <p><b>Projects through one keyset listing</b>, ordered by id: an offset listing past fifty thousand rows is
 * refused by GitLab, and a keyset one does not shift when a project is created between two pages. {@code
 * statistics=true} asks for the size, which GitLab gives a Reporter only: where it does not, the size is unknown,
 * never zero.
 *
 * <p><b>What GitLab leaves out stays unknown.</b> A fork is named only when the token can read its source
 * ({@code forked_from_project}); a project without the field is stored {@code fork = null}, not {@code false}. An
 * empty repository has no default branch. The language costs one request per project and is asked only of the
 * projects that are new or active since it was last read; a 403 or a 404 there leaves it unknown and the run goes
 * on — a project whose code a Guest token cannot read is still a project.
 *
 * <p><b>A personal namespace</b> ({@code namespace.kind = user}) is listed and flagged, for the selection to
 * offer unticked (answer 7).
 */
@Component
class GitLabLister implements ForgeLister {

    /** GitLab's Guest. A Reporter is what the token should hold; a Guest's projects are listed all the same. */
    static final int MIN_ACCESS_LEVEL = 10;

    static final String GROUPS = "/groups?min_access_level=" + MIN_ACCESS_LEVEL + "&order_by=id&sort=asc&per_page=100";

    static final String PROJECTS = "/projects?membership=true&min_access_level=" + MIN_ACCESS_LEVEL
            + "&statistics=true&pagination=keyset&order_by=id&sort=asc&per_page=100";

    @Override
    public ForgeKind kind() {
        return ForgeKind.GITLAB;
    }

    @Override
    public void list(Listing listing) {
        String api = listing.target().address().apiRoot();
        OutboundPager pager = listing.pager(Map.of("PRIVATE-TOKEN", listing.token()));

        walk(pager, api + GROUPS, "the groups", group -> {
            String path = text(group, "full_path");
            if (path != null) {
                listing.namespace(path);
            }
        }, page -> {});

        walk(pager, api + PROJECTS, "the projects", project -> {}, page -> {
            List<DiscoveredRepository> repositories = new ArrayList<>();
            for (JsonNode project : page) {
                DiscoveredRepository repository = repositoryOf(project);
                listing.namespace(repository.namespacePath());
                repositories.add(repository);
            }
            listing.repositories(repositories);
        });

        for (String forgeId : listing.languagesWanted()) {
            OutboundJson.Answer answer = pager.get(api + "/projects/" + forgeId + "/languages");
            switch (answer.status()) {
                case 200 -> listing.language(forgeId, mainLanguage(answer.body().orElse(null)));
                case 401 -> throw rejected();
                // A Guest cannot read a private project's code, nor its languages; a project gone since the listing
                // has none either. Unknown, and the run goes on.
                default -> listing.language(forgeId, null);
            }
        }
    }

    /** Reads every page of a listing, handing each element and then each page to the callers. */
    private static void walk(
            OutboundPager pager, String first, String what, Consumer<JsonNode> each, Consumer<JsonNode> perPage) {
        Optional<String> url = Optional.of(first);
        while (url.isPresent()) {
            OutboundJson.Answer answer = pager.get(url.get());
            switch (answer.status()) {
                case 200 -> {
                    // Read below.
                }
                case 401 -> throw rejected();
                case 403, 404 -> throw new ForgeListingException(DiscoveryReason.FORGE_REFUSED, "GitLab refused to list "
                        + what + " with this token (HTTP " + answer.status() + "): it needs the read_api scope.");
                default -> throw new ForgeListingException(DiscoveryReason.FORGE_REFUSED,
                        "GitLab answered the listing of " + what + " with HTTP " + answer.status() + ".");
            }
            JsonNode page = answer.body().filter(JsonNode::isArray).orElseThrow(() -> new ForgeListingException(
                    DiscoveryReason.FORGE_UNAVAILABLE, "GitLab answered the listing of " + what + " with no list."));
            for (Iterator<JsonNode> elements = page.elements(); elements.hasNext(); ) {
                each.accept(elements.next());
            }
            perPage.accept(page);
            url = pager.next(answer, url.get(), OutboundPager.NextPage.GITLAB);
        }
    }

    static DiscoveredRepository repositoryOf(JsonNode project) {
        String fullPath = orEmpty(text(project, "path_with_namespace"));
        JsonNode namespace = project.path("namespace");
        String namespacePath = text(namespace, "full_path");
        if (namespacePath == null) {
            int slash = fullPath.lastIndexOf('/');
            namespacePath = slash < 0 ? "" : fullPath.substring(0, slash);
        }
        JsonNode size = project.path("statistics").path("repository_size");
        return new DiscoveredRepository(
                project.path("id").isIntegralNumber() ? project.path("id").asText() : orEmpty(text(project, "id")),
                fullPath,
                namespacePath,
                "user".equals(text(namespace, "kind")),
                Optional.ofNullable(text(project, "name")).orElse(orEmpty(text(project, "path"))),
                text(project, "default_branch"),
                project.path("archived").isBoolean() ? project.path("archived").asBoolean() : null,
                project.path("forked_from_project").isObject() ? Boolean.TRUE : null,
                text(project, "visibility"),
                instant(text(project, "last_activity_at")),
                null,
                size.isIntegralNumber() ? size.asLong() : null,
                text(project, "http_url_to_repo"),
                text(project, "ssh_url_to_repo"),
                text(project, "web_url"));
    }

    /** The language with the largest share; none when GitLab reports none. */
    static String mainLanguage(JsonNode languages) {
        if (languages == null || !languages.isObject()) {
            return null;
        }
        String best = null;
        double share = -1;
        for (Map.Entry<String, JsonNode> entry : languages.properties()) {
            if (entry.getValue().isNumber() && entry.getValue().asDouble() > share) {
                best = entry.getKey();
                share = entry.getValue().asDouble();
            }
        }
        return best;
    }

    private static ForgeListingException rejected() {
        return new ForgeListingException(DiscoveryReason.TOKEN_REJECTED,
                "GitLab rejected this token (HTTP 401): it is wrong, expired or revoked. Replace it on the connection.");
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
