package com.asmolabs.vectispire.common.domain.access;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.util.List;
import java.util.Objects;

/**
 * A project or a solution <b>as far as the caller sees it</b>: the targets filed in it that the caller
 * may see, and whether it holds others (decision 0023: "a partial grant sees a partial project, and
 * says so").
 *
 * <p><b>Not {@link VisibleProject}.</b> That one is a project seen <em>whole</em>, for the checklists,
 * whose lines speak for every repository and are refused to a partial reader. This one is what the
 * aggregates read — a project's figures, its compliance, its consolidated inventory — each computed
 * over {@link #targets()} and marked {@link #partial()} where the caller does not see all of it, like
 * the tree and the backlog. Every input of those aggregates is narrowed to the visible targets, so a
 * partial figure says nothing of the hidden ones but that they exist, which {@code partial} says
 * already.
 *
 * <p><b>Minted by the guard alone</b>, like {@link VisibleTarget}: only {@code RowVisibility}, having
 * refused a project or a solution that is absent or of which the caller sees nothing in one sentence,
 * builds one ({@code ArchitectureTest.visibleTargetsAreMintedByTheGuard}). A service that may not use
 * {@code access} — {@code inventory}, {@code exports} — takes this from its route, never a bare id.
 *
 * @param kind a project or a solution
 * @param id its identifier
 * @param name its name, as a document or a response states it
 * @param targets the targets filed in it now that the caller may see — repositories then images, each
 *     in ascending order; empty for a project filed with nothing, or holding only hidden targets and
 *     granted as such
 * @param partial it holds targets the caller does not see; whatever is computed over {@code targets}
 *     covers only those
 */
public record VisibleScope(Kind kind, long id, String name, List<ScanTarget> targets, boolean partial) {

    /** What a scope is; its wire name is the one a response carries in {@code kind}. */
    public enum Kind {
        PROJECT("project"),
        SOLUTION("solution");

        private final String wireName;

        Kind(String wireName) {
            this.wireName = wireName;
        }

        public String wireName() {
            return wireName;
        }
    }

    public VisibleScope {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(name, "name");
        targets = List.copyOf(targets);
    }

    /**
     * The visibility every read over this scope is narrowed by: its visible targets and nothing else.
     * An empty scope is {@code Only} of nothing, which every query answers with nothing — never
     * "unrestricted", which is what an empty filter read the other way would give.
     */
    public Visibility visibility() {
        return Visibility.only(targets);
    }
}
