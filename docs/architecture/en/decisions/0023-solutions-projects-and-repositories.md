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
- Containers are not attached to projects in this step (they are since the amendment of 2026-09-30
  below).

## Consequences

- Moving a repository from one project to another moves its visibility for project grantees at
  once, in both directions — the audit entry for the move says so.
- Deleting a project detaches its repositories (they return to "no project"); it deletes no
  repository and no finding. Deleting a solution requires it to be empty.
- Aggregates per project and per solution (issues, scores, compliance, consolidated SBOM) are
  computed over the member repositories the reader may see — a partial grant sees a partial project,
  and says so.

## Amendment (2026-09-30) — container images join projects

**The gap.** A product is its repositories *and* the images built from them, and several features
already speak of "a project's targets": a grant on a project, the backlog's `project_id` and
`solution_id` filters, the tree's figures, the move of a project to another solution. With images
outside every project, a grantee was shown a product's source and not what runs in production, and
a project's backlog left out the findings the images carry.

**The decision.**

- **An image is filed in at most one project, like a repository.** A nullable `t_container.project_id`
  (V59), with a named foreign key `fk_container_project … on delete set null` and an index, written
  three times (`db/migration/{postgresql,mysql,sqlite}/`) since a foreign key is structure that diverges
  (decision 0027). Existing images start in no project; nothing is inferred. The entity maps the column
  read-only and two targeted updates write it, for the reason given for repositories: a save of a form
  read before a move must not move the image back.
- **The routes mirror the repositories'**: `PUT` and `DELETE /api/v1/projects/{id}/containers/{containerId}`,
  administrators only, 204; an image the caller cannot see answers the 404 an absent one gets ("Target
  not found."), one that is not in that project a 404 of its own; filing it where it is records nothing.
- **Audited as `PROJECT_CONTAINERS_CHANGED`, an operation of its own** rather than
  `PROJECT_REPOSITORIES_CHANGED` reused: the entry's resource is the image's identifier, and a
  repository and an image may carry the same number — under the repositories' operation "42" would name
  the wrong target to whoever filtered the log. It signals `ACCESS_GRANT_CHANGED` to the SIEM, like its
  sibling, and its words say that visibility moves.
- **A project grant resolves into the project's repositories and images**, at each request, in
  `VisibilityService`, as before: the `Visibility` is still a set of targets and every route narrowing
  by it narrows images without change. So a reader granted a project gains its images — intended —
  loses one the moment it leaves the project, and a move between projects moves it from one project's
  grantees to the other's, with no grant row touched. The lookup binds a thousand projects at a time.
- **The tree lists them**: each `ProjectNode` carries `containerCount` and `containers` (`id`, `name`),
  the "no project" group lists the unfiled images the reader sees, and every `openIssues` — project,
  solution, unfiled — counts the listed images' open issues beside the repositories'. `repositoryCount`
  stays a count of repositories; `partial` is set when a repository **or** an image is hidden.
- **What follows a project follows its images**: the backlog's `project_id` and `solution_id` include
  their issues (each target matched by its own column, written into the statement as literals); moving
  a project carries them, since only `t_container.project_id` names it; deleting a project returns them
  to "no project", explicitly, and the audit entry counts them; a team granted a project is notified of
  its images' scans as it is of its repositories'.
- **What does not move in this lot, deliberately**: the **checklists**. Their measurements are taken
  over the project's repositories (`ProjectMembers.repositoryIds`), and so is the guard that serves a
  checklist only to a reader who sees the whole project. A signed checklist document states what was
  measured, and images entering the scope would change what an answer already given speaks for without
  anybody deciding it. The languages union and the plugins activated for a project stay
  repository-shaped too: an image carries no language census, and a plugin runs on a source tree.

**Open point.** Most checklist rules are repository-shaped (static analysis, coverage, tests,
languages); the dependency analysis and the findings thresholds over vulnerability scopes could
meaningfully include images. Deciding that is a change to the measurements *and* to the whole-project
guard together — a reader who sees every repository and not the image would then be refused — and is
left to a decision of its own.
