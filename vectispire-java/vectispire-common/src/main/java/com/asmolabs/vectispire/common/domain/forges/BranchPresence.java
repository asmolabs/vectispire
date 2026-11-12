package com.asmolabs.vectispire.common.domain.forges;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Which of the tracked branches — {@code main}, {@code master}, {@code develop} unless an installation names others
 * — one discovered repository has, as far as a discovery read it (decision 0037 §3–5). The selection filters on it,
 * and an import naming branches creates a target only on one that is present.
 *
 * <p><b>Unknown is not absent</b> (decision 0007, as for every field of the snapshot). A branch is present when it
 * is the default branch the forge names — no request asks that — or when the reading found it; absent only when the
 * reading asked the forge about it and was told it does not exist. Everything else is unknown: a repository whose
 * branches were never read, one where any request of the reading went unanswered or was refused ({@code present}
 * null), and a name the reading did not ask — an installation that tracks {@code trunk} since its last discovery
 * knows nothing yet of {@code trunk}.
 *
 * @param defaultBranch the default branch the forge names; null for an empty repository
 * @param asked the tracked names the reading asked about; null when the branches were never read
 * @param present the tracked names it found; null when the forge did not answer for every one of them
 */
public record BranchPresence(String defaultBranch, Set<String> asked, Set<String> present) {

    /** The most names an installation tracks: each costs up to one request per repository per discovery. */
    public static final int MAX_TRACKED = 10;

    /** A branch name's width, as {@code t_repository.branch} holds it. */
    public static final int NAME_LENGTH = 255;

    /** How an import names the default branch whatever it is called; never a tracked name. */
    public static final String DEFAULT_WORD = "default";

    /** What a reading says of one name. */
    public enum Answer {
        PRESENT,
        ABSENT,
        UNKNOWN
    }

    public BranchPresence {
        asked = asked == null ? null : Collections.unmodifiableSet(new TreeSet<>(asked));
        present = present == null ? null : Collections.unmodifiableSet(new TreeSet<>(present));
    }

    /** A snapshot row's columns, as {@link #encode} wrote them. */
    public static BranchPresence stored(String defaultBranch, String asked, String present) {
        return new BranchPresence(defaultBranch, decode(asked), decode(present));
    }

    public Answer of(String name) {
        if (name.equals(defaultBranch)) {
            return Answer.PRESENT;
        }
        if (asked == null || present == null || !asked.contains(name)) {
            return Answer.UNKNOWN;
        }
        return present.contains(name) ? Answer.PRESENT : Answer.ABSENT;
    }

    /**
     * Names as a column holds them: sorted, comma-separated — the empty text for none, which is an answer, and null
     * for null, which is not. A tracked name holds no comma ({@link #refusal}).
     */
    public static String encode(Collection<String> names) {
        return names == null ? null : names.stream().sorted().distinct().collect(Collectors.joining(","));
    }

    /** {@link #encode}'s inverse. */
    public static Set<String> decode(String stored) {
        if (stored == null) {
            return null;
        }
        return stored.isEmpty() ? Set.of()
                : Arrays.stream(stored.split(",")).filter(name -> !name.isEmpty()).collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Why a value cannot be a tracked branch name, or null when it can: empty, longer than a target's branch column,
     * holding whitespace or a comma (the column's separator), or the word that names the default branch.
     */
    public static String refusal(String name) {
        if (name == null || name.isEmpty()) {
            return "a tracked branch name is empty";
        }
        if (name.length() > NAME_LENGTH) {
            return "a tracked branch name is longer than " + NAME_LENGTH + " characters";
        }
        if (name.chars().anyMatch(c -> Character.isWhitespace(c) || Character.isISOControl(c) || c == ',')) {
            return "a tracked branch name holds whitespace, a control character or a comma";
        }
        if (name.equals(DEFAULT_WORD)) {
            return "\"" + DEFAULT_WORD + "\" names the default branch, whatever it is called, and cannot be tracked";
        }
        return null;
    }
}
