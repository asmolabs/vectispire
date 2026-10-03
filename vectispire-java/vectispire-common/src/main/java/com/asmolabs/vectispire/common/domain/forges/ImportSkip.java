package com.asmolabs.vectispire.common.domain.forges;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Why a discovered repository is not offered, or not imported, as a new target (decision 0037 §4–5). The selection
 * shows it greyed with this word; an import that was asked for it skips it and reports the word, and replaying an
 * import is therefore harmless: everything it created is skipped the second time.
 */
public enum ImportSkip {
    /** Linked to a target by an earlier import from this connection — recognised by the forge's id, renamed or not. */
    ALREADY_IMPORTED("already_imported"),
    /**
     * Its HTTPS or its SSH clone URL has the identity of an existing target's URL ({@code RepositoryUrl.identity}),
     * whatever that target's branch and sub-path: typed by hand, or a monorepo already split into sub-path targets.
     */
    ALREADY_PRESENT("already_present"),
    /** No default branch: on GitLab, an empty repository — there is nothing to clone yet. */
    NO_DEFAULT_BRANCH("no_default_branch"),
    /** The forge gave no clone URL of the kind the credential chosen for its host needs. */
    NO_CLONE_URL("no_clone_url"),
    /** Another repository of the same selection has the same identity, and is the one imported. */
    DUPLICATE_IN_SELECTION("duplicate_in_selection");

    private final String wireName;

    ImportSkip(String wireName) {
        this.wireName = wireName;
    }

    @JsonValue
    public String wireName() {
        return wireName;
    }
}
