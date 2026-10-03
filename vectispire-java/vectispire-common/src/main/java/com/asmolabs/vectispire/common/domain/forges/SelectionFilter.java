package com.asmolabs.vectispire.common.domain.forges;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * The filters of the selection table (decision 0037 §4): what a person narrows a discovery's repositories to
 * before ticking them. A filter decides what is <em>shown</em>; what is imported is what was ticked, never what a
 * filter matches at import time.
 *
 * <p><b>Unknown is never judged — either way.</b> The rule of decision 0007 applied to a filter: GitLab names a
 * fork's source only when the token can read it, gives no size without a Reporter and no language without one
 * more request; Bitbucket Cloud has no archived flag at all. A filter that <em>hides</em> something (archived,
 * forks, inactive) keeps a repository it cannot judge, and one that <em>requires</em> something (only archived, a
 * language, a visibility) leaves it out — and either way the repository is counted against that filter as
 * unjudged, so the screen can say how many it could not tell. Hiding every repository whose fork flag GitLab did
 * not state would hide nearly every repository of a GitLab; keeping every repository of unknown language under
 * "Java" would show a list that is not Java.
 *
 * @param archived archived repositories: hidden by default
 * @param forks forks: hidden by default
 * @param inactiveDays hides a repository whose last activity is older than this many days; null shows them all
 * @param language only this primary language, as the forge names it, case aside
 * @param visibility only this visibility ({@code public}, {@code internal}, {@code private}), case aside
 * @param namespace only this namespace and what lies below it, by whole segments, case aside
 * @param path a pattern on the full path, case aside: {@code *} any run of characters, slashes included, and
 *     {@code ?} one; without either, the path need only contain it
 * @param personal repositories in a user's own namespace: shown by default
 * @param present repositories already a target: shown by default — greyed and not selectable
 */
public record SelectionFilter(
        Shown archived,
        Shown forks,
        Integer inactiveDays,
        String language,
        String visibility,
        String namespace,
        String path,
        Shown personal,
        Shown present) {

    /** Ten years: past that the filter hides nothing a forge still holds. */
    public static final int MAX_INACTIVE_DAYS = 3_650;

    /** Whether a kind of repository is shown, hidden, or the only one shown. */
    public enum Shown {
        HIDE,
        SHOW,
        ONLY;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }

        /** A reader's word; blank is the filter's default. */
        static Shown parse(String raw, Shown byDefault, String what) {
            if (raw == null || raw.isBlank()) {
                return byDefault;
            }
            String wanted = raw.trim().toLowerCase(Locale.ROOT);
            return Arrays.stream(values()).filter(shown -> shown.wireName().equals(wanted)).findFirst()
                    .orElseThrow(() -> new InvalidInputException("\"" + BoundedText.clip(raw.trim(), 40) + "\" is not "
                            + "a choice for " + what + ": hide, show or only."));
        }
    }

    /** The filters that may meet a value the forge did not give. */
    public enum Judged {
        ARCHIVED,
        FORK,
        ACTIVITY,
        LANGUAGE,
        VISIBILITY;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** What the table shows before anybody touches a filter: no archived repository, no fork. */
    public static final SelectionFilter DEFAULT =
            new SelectionFilter(Shown.HIDE, Shown.HIDE, null, null, null, null, null, Shown.SHOW, Shown.SHOW);

    /** The filters as a request spells them, each refused in words. */
    public static SelectionFilter parse(
            String archived, String forks, Integer inactiveDays, String language, String visibility, String namespace,
            String path, String personal, String present) {
        if (inactiveDays != null && (inactiveDays < 1 || inactiveDays > MAX_INACTIVE_DAYS)) {
            throw new InvalidInputException("inactiveDays is a number of days between 1 and " + MAX_INACTIVE_DAYS + ".");
        }
        return new SelectionFilter(
                Shown.parse(archived, Shown.HIDE, "archived"),
                Shown.parse(forks, Shown.HIDE, "forks"),
                inactiveDays,
                BoundedText.optional(language, DiscoveredRepository.LANGUAGE_LENGTH, "The language"),
                BoundedText.optional(visibility, DiscoveredRepository.VISIBILITY_LENGTH, "The visibility"),
                Optional.ofNullable(BoundedText.optional(namespace, DiscoveredRepository.PATH_LENGTH, "The namespace"))
                        .map(SelectionFilter::withoutSlashes).orElse(null),
                BoundedText.optional(path, DiscoveredRepository.PATH_LENGTH, "The path pattern"),
                Shown.parse(personal, Shown.SHOW, "personal"),
                Shown.parse(present, Shown.SHOW, "present"));
    }

    /**
     * One repository as the filters see it.
     *
     * @param present already a target, by identity or by an earlier import
     */
    public record Candidate(
            Boolean archived,
            Boolean fork,
            Instant lastActivityAt,
            String language,
            String visibility,
            String namespacePath,
            String fullPath,
            boolean personal,
            boolean present) {}

    /**
     * How the filters judged one repository.
     *
     * @param matches every filter keeps it
     * @param unjudged the filters that met an unknown value and passed every other filter — what the screen counts
     *     per filter, so that "N repositories of unknown language are not shown" is a figure, not a guess
     */
    public record Verdict(boolean matches, Set<Judged> unjudged) {}

    /** Judged at {@code now}, which places the inactivity cut. */
    public Verdict judge(Candidate candidate, Instant now) {
        Set<Judged> failed = EnumSet.noneOf(Judged.class);
        Set<Judged> unknown = EnumSet.noneOf(Judged.class);
        boolean others = true;

        judgeShown(archived, candidate.archived(), Judged.ARCHIVED, failed, unknown);
        judgeShown(forks, candidate.fork(), Judged.FORK, failed, unknown);
        if (inactiveDays != null) {
            if (candidate.lastActivityAt() == null) {
                unknown.add(Judged.ACTIVITY);
            } else if (candidate.lastActivityAt().isBefore(now.minus(Duration.ofDays(inactiveDays)))) {
                failed.add(Judged.ACTIVITY);
            }
        }
        judgeRequired(language, candidate.language(), Judged.LANGUAGE, failed, unknown);
        judgeRequired(visibility, candidate.visibility(), Judged.VISIBILITY, failed, unknown);

        if (namespace != null) {
            String wanted = namespace.toLowerCase(Locale.ROOT);
            String actual = withoutSlashes(candidate.namespacePath()).toLowerCase(Locale.ROOT);
            others &= actual.equals(wanted) || actual.startsWith(wanted + "/");
        }
        if (path != null) {
            others &= pathMatches(path, candidate.fullPath());
        }
        others &= shows(personal, candidate.personal());
        others &= shows(present, candidate.present());

        boolean matches = others && failed.isEmpty();
        Set<Judged> unjudged = EnumSet.noneOf(Judged.class);
        if (others) {
            // Counted only where nothing else would have hidden the repository anyway: the figure says how many
            // this filter alone could not judge.
            for (Judged filter : unknown) {
                Set<Judged> rest = EnumSet.copyOf(failed);
                rest.remove(filter);
                if (rest.isEmpty()) {
                    unjudged.add(filter);
                }
            }
        }
        return new Verdict(matches, unjudged);
    }

    /** A hiding filter keeps the unknown; an "only" filter leaves it out; both count it. */
    private static void judgeShown(Shown shown, Boolean value, Judged filter, Set<Judged> failed, Set<Judged> unknown) {
        if (shown == Shown.SHOW) {
            return;
        }
        if (value == null) {
            unknown.add(filter);
            if (shown == Shown.ONLY) {
                failed.add(filter);
            }
            return;
        }
        if (shown == Shown.HIDE ? value : !value) {
            failed.add(filter);
        }
    }

    private static void judgeRequired(String wanted, String value, Judged filter, Set<Judged> failed, Set<Judged> unknown) {
        if (wanted == null) {
            return;
        }
        if (value == null) {
            unknown.add(filter);
            failed.add(filter);
        } else if (!value.equalsIgnoreCase(wanted)) {
            failed.add(filter);
        }
    }

    private static boolean shows(Shown shown, boolean value) {
        return switch (shown) {
            case SHOW -> true;
            case HIDE -> !value;
            case ONLY -> value;
        };
    }

    /**
     * {@code acme/payments/*}: a glob over the whole path, {@code *} crossing slashes, case aside. Without a
     * wildcard, a search: the path contains it.
     *
     * <p><b>Matched by hand, not by a regular expression.</b> A pattern of many stars compiled to {@code .*} runs
     * backtracks exponentially on a long path that almost matches; this walk is at most the pattern's length times
     * the path's — both bounded by the column, a thousand characters each.
     */
    static boolean pathMatches(String pattern, String fullPath) {
        String path = fullPath.toLowerCase(Locale.ROOT);
        String wanted = pattern.toLowerCase(Locale.ROOT);
        if (wanted.indexOf('*') < 0 && wanted.indexOf('?') < 0) {
            return path.contains(wanted);
        }
        int p = 0;
        int w = 0;
        int star = -1;
        int resume = 0;
        while (p < path.length()) {
            if (w < wanted.length() && (wanted.charAt(w) == '?' || wanted.charAt(w) == path.charAt(p))) {
                p++;
                w++;
            } else if (w < wanted.length() && wanted.charAt(w) == '*') {
                star = w++;
                resume = p;
            } else if (star >= 0) {
                w = star + 1;
                p = ++resume;
            } else {
                return false;
            }
        }
        while (w < wanted.length() && wanted.charAt(w) == '*') {
            w++;
        }
        return w == wanted.length();
    }

    private static String withoutSlashes(String value) {
        String trimmed = value.trim();
        int start = 0;
        int end = trimmed.length();
        while (start < end && trimmed.charAt(start) == '/') {
            start++;
        }
        while (end > start && trimmed.charAt(end - 1) == '/') {
            end--;
        }
        return trimmed.substring(start, end);
    }
}
