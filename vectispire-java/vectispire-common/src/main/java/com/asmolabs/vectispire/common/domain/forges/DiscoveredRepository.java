package com.asmolabs.vectispire.common.domain.forges;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * One repository as a forge listed it (decision 0037 §3): its stable id, where it lives, and what the forge
 * said about it.
 *
 * <p><b>Unknown is not zero</b> — decision 0007's rule applied to metadata. Every component but the id, the
 * paths and the name is {@code null} when the forge did not give it: GitLab states a size only to a Reporter,
 * a language only through one more request, a fork only when the token can read its source, a default
 * branch only for a repository that has commits. A {@code null} is stored {@code null} and shown
 * <em>unknown</em>, never read as small, language-less, not a fork or inactive.
 *
 * @param forgeId the forge's own id — stable across renames and moves, what the snapshot is keyed by
 * @param fullPath {@code group/subgroup/name}, as the forge writes it
 * @param namespacePath the namespace holding it, {@code group/subgroup}
 * @param personal held in a user's own namespace rather than a group's or an organisation's: listed, flagged,
 *     and offered unticked by the selection (decision 0037, answer 7)
 * @param sizeBytes the repository's size in bytes
 */
public record DiscoveredRepository(
        String forgeId,
        String fullPath,
        String namespacePath,
        boolean personal,
        String name,
        String defaultBranch,
        Boolean archived,
        Boolean fork,
        String visibility,
        Instant lastActivityAt,
        String language,
        Long sizeBytes,
        String httpUrl,
        String sshUrl,
        String webUrl) {

    /** The widths of the snapshot's columns. */
    public static final int FORGE_ID_LENGTH = 64;
    public static final int PATH_LENGTH = 1000;
    public static final int NAME_LENGTH = 255;
    public static final int BRANCH_LENGTH = 255;
    public static final int VISIBILITY_LENGTH = 20;
    public static final int LANGUAGE_LENGTH = 100;
    public static final int URL_LENGTH = 1024;

    /** The earliest and latest instants a timestamp column holds on every engine. */
    private static final Instant EARLIEST = Instant.parse("1970-01-02T00:00:00Z");
    private static final Instant LATEST = Instant.parse("9999-12-30T00:00:00Z");

    public DiscoveredRepository {
        Objects.requireNonNull(forgeId, "forgeId");
        Objects.requireNonNull(fullPath, "fullPath");
        Objects.requireNonNull(namespacePath, "namespacePath");
        Objects.requireNonNull(name, "name");
    }

    /**
     * Why this repository cannot be kept, if it cannot: an id, a path or a name longer than its column. Kept
     * cut, a path would name another repository — so it is skipped, and counted as skipped.
     */
    public Optional<String> unstorable() {
        if (forgeId.isBlank() || forgeId.length() > FORGE_ID_LENGTH) {
            return Optional.of("its id is empty or longer than " + FORGE_ID_LENGTH + " characters");
        }
        if (fullPath.isBlank() || fullPath.length() > PATH_LENGTH || namespacePath.length() > PATH_LENGTH) {
            return Optional.of("its path is empty or longer than " + PATH_LENGTH + " characters");
        }
        if (name.isBlank() || name.length() > NAME_LENGTH) {
            return Optional.of("its name is empty or longer than " + NAME_LENGTH + " characters");
        }
        return Optional.empty();
    }

    /**
     * The same repository with every optional value its column cannot hold made unknown: a branch, a URL or a
     * language cut short would be a wrong value, and a wrong value is worse than an unknown one. An instant a
     * timestamp column cannot hold on every engine is unknown too.
     */
    public DiscoveredRepository bounded() {
        return new DiscoveredRepository(forgeId, fullPath, namespacePath, personal, name,
                within(defaultBranch, BRANCH_LENGTH), archived, fork, within(visibility, VISIBILITY_LENGTH),
                lastActivityAt == null || lastActivityAt.isBefore(EARLIEST) || lastActivityAt.isAfter(LATEST)
                        ? null : lastActivityAt,
                within(language, LANGUAGE_LENGTH), sizeBytes == null || sizeBytes < 0 ? null : sizeBytes,
                within(httpUrl, URL_LENGTH), within(sshUrl, URL_LENGTH), within(webUrl, URL_LENGTH));
    }

    /**
     * What changed since the snapshot's previous reading of this repository, in words; empty when nothing the
     * comparison follows did (decision 0037 §3: renamed or moved, default branch changed, archived).
     *
     * <p><b>An unknown is not a change</b>: a default branch the forge did not state this time is not a branch
     * changed, and an archived flag it did not give is not one unarchived.
     *
     * @param wasGone the repository had been marked gone by an earlier completed run: seeing it again is a change
     */
    public List<String> changesSince(String previousPath, String previousBranch, Boolean previousArchived, boolean wasGone) {
        List<String> changes = new ArrayList<>();
        if (wasGone) {
            changes.add("seen again after it was gone");
        }
        if (previousPath != null && !previousPath.equals(fullPath)) {
            changes.add("renamed or moved from " + previousPath);
        }
        if (previousBranch != null && defaultBranch != null && !previousBranch.equals(defaultBranch)) {
            changes.add("default branch " + previousBranch + " → " + defaultBranch);
        }
        if (previousArchived != null && archived != null && !previousArchived.equals(archived)) {
            changes.add(archived ? "archived" : "unarchived");
        }
        return changes;
    }

    private static String within(String value, int length) {
        return value == null || value.isBlank() || value.length() > length ? null : value;
    }
}
