package com.asmolabs.vectispire.common.domain.access;

/**
 * A project the caller may see <b>whole</b>: every repository in it, or the project granted as such.
 *
 * <p><b>Why whole, and not "some of it".</b> A project checklist speaks for every repository of its
 * project, and its measurements carry figures from each (decision 0032 §8). A reader who sees part of
 * a project would read, in one line, the state of repositories hidden from them — "no: repository X
 * still has a critical" — so the project's checklists are refused to them as if it did not exist.
 *
 * <p><b>Minted by the guard alone</b>, like {@link VisibleTarget}: only {@code
 * RowVisibility.requireWhollyVisibleProject} builds one, having refused a project that is absent or
 * not wholly visible in one sentence ({@code ArchitectureTest.visibleTargetsAreMintedByTheGuard}). A
 * checklist service takes this, never a bare project id, so no caller reaches a project's checklists
 * without the check having run.
 *
 * @param projectId the project
 * @param name its name, as the checklist's header states the product
 */
public record VisibleProject(long projectId, String name) {}
