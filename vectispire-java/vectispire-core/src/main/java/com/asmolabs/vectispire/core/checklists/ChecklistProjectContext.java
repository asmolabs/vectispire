package com.asmolabs.vectispire.core.checklists;

/**
 * What a project's checklist page shows before it has a checklist to show: the project, named as a
 * checklist's header names the product, and where its newest revision stands.
 *
 * <p><b>A route of its own rather than a field on the list or the offered versions.</b> Both answer
 * a bare array, which a client already reads; wrapping either in an object to carry a name breaks
 * every client, and repeating the name on each element leaves it absent exactly when the page needs
 * it — a project with no checklist, or an organisation with no published version.
 *
 * @param latestRevision the newest revision's number; null while the project has no checklist
 * @param latestEdition the newest revision's edition — what opening or moving the checklist names as
 *     the one read; null while the project has no checklist, which is what opening one then names
 */
public record ChecklistProjectContext(long projectId, String projectName, Integer latestRevision, Integer latestEdition) {}
