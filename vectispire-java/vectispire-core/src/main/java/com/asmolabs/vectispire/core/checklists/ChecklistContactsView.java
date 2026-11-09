package com.asmolabs.vectispire.core.checklists;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * A project's checklist profiles and the accounts linked to them (decision 0044).
 *
 * @param revision the revision whose template version named the profiles — the project's newest; null
 *     while the project has no checklist, when there are no profiles either
 * @param draft whether that revision is a draft, the only state in which lines are filled in and reminded of
 * @param profiles each profile the version's contact column names, but {@code AUTO}, in the column's order
 */
public record ChecklistContactsView(
        long projectId,
        @Schema(types = {"integer", "null"}, format = "int32", description = "The newest revision, whose version named "
                + "the profiles; null while the project has no checklist.")
                Integer revision,
        boolean draft,
        List<ChecklistContactView> profiles) {

    public ChecklistContactsView {
        profiles = List.copyOf(profiles);
    }
}
