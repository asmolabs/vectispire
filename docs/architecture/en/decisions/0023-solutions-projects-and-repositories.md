# 0023 — Solutions contain projects, a project references repositories, and a grant may name a project

**Date:** 2026-09-25 · **Status:** accepted · **Decider:** Laurent Boucher

## Context

Everything in Vectispire hangs off a scan target — a repository or a container image. That is the
right unit for scanning and the wrong one for everything organisations ask of it afterwards: a
product is several repositories, a report is written for a product, and an access grant made
repository by repository has to be repeated every time a product gains one. Reports and checklists
(the reporting plugins that follow this decision) are written **per project**, so a project has to
exist first.

## Decision

- **A solution contains projects; a project references repositories.** Two new tables,
  `t_solution` and `t_project` (a project belongs to exactly one solution), and a nullable
  `project_id` on `t_repository`.
- **A repository belongs to at most one project.** A column, not a link table: a finding, a score or
  a report must add up to one project without double counting, and "which project is this in" must
  have one answer.
- **Existing repositories start with no project.** Nothing is inferred from names or URLs; an
  administrator files them. Every screen and aggregate treats "no project" explicitly rather than
  hiding those repositories.
- **A grant may name a project** — to an account or a team, next to the repository and container
  grants that exist. It is resolved at each request into the project's repositories *at that
  moment*, so a repository added to a project becomes visible to whoever holds the project, with
  nothing re-granted. Repository grants keep working; visibility is the **union** of the two. There
  is **no grant on a solution**: one level of inheritance is enough to audit, and a solution-wide
  grant is a list of project grants an administrator can see.
- The resolution happens in `VisibilityService`, before any query: the `Visibility` passed to
  queries is still a set of targets, so every route that already narrows by visibility narrows
  projects' repositories correctly without being changed, and a refusal is still a 404.
- Containers are not attached to projects in this step.

## Consequences

- Moving a repository from one project to another moves its visibility for project grantees at
  once, in both directions — the audit entry for the move says so.
- Deleting a project detaches its repositories (they return to "no project"); it deletes no
  repository and no finding. Deleting a solution requires it to be empty.
- Aggregates per project and per solution (issues, scores, compliance, consolidated SBOM) are
  computed over the member repositories the reader may see — a partial grant sees a partial project,
  and says so.
