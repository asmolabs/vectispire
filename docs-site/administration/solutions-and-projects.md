# Solutions and projects

Vectispire scans repositories one at a time, but people ask about products: *how exposed is the
payments platform*, *who can see the mobile app*. Solutions and projects are how you tell Vectispire
what the products are.

## The model

- A **solution** holds **projects** — a product line, a platform, a customer offering.
- A **project** belongs to exactly one solution and references the **repositories** that make it up.
- A repository is in **at most one project**. That is deliberate: a figure or a report must add up
  to one project without counting anything twice, and "which project is this in" must have one
  answer.
- Container images are not attached to projects yet.

Names are unique regardless of case: a solution's across the installation, a project's within its
solution. Two solutions may each hold an "API". A name already taken is refused the same way whether
it is being created, renamed or moved into a solution: `409`, with the type
`urn:vectispire:problem:solution-name-taken` for a solution and
`urn:vectispire:problem:project-name-taken` for a project, and the dialog stays open saying which name
is taken.

## "No project"

Repositories that existed before you created any project start with **no project**. Nothing is
inferred from their names or URLs — an administrator files them.

"No project" is a group of its own everywhere it appears, never hidden: the tree lists those
repositories under it, with their open issues, so a filing that is not finished looks unfinished.

## Filing, moving and removing a repository

Only administrators change the tree. Filing a repository into a project moves it out of any
project it was in; removing it returns it to "no project".

**Filing is an access change.** A grant on a project covers the repositories in the project *at
the time of each request* (see below), so moving a repository from one project to another takes it
away from the first project's holders and gives it to the second's, at once. The audit log records
every move in those words, under `PROJECT_REPOSITORIES_CHANGED`.

## Moving a project to another solution

An administrator can move a project to another solution. **Everything the project holds goes with
it**: its repositories stay filed in it, and its grants, its checklists, the plugins switched on for
it and the SARIF sources scoped to it all name the project, not the solution, so none of them
changes. **Nobody gains or loses sight of anything**: there is no grant on a solution, so a move
only changes where the project is drawn in the tree — and which solution's figures and issue filter
count it, from the next request on.

The move is refused when the target solution already holds a project of the same name, case aside
(rename one of the two first), and a solution that does not exist is answered as absent. Moving a
project to the solution it is already in changes nothing. The audit log records the move under
`PROJECT_UPDATED`, naming both solutions.

## Grants on a project

In [Users and teams](users-and-teams.md#what-a-grant-names), an account or a team can be granted a
project, next to individual repositories and images:

- The grant covers **every repository in the project at the moment of each request**. A repository
  filed into the project next month is visible to the project's holders the moment it is filed,
  with nothing re-granted.
- Grants **add up**: what someone sees is the union of their repository, image and project grants,
  direct and through their teams.
- There is **no grant on a solution**. One level of inheritance is what an auditor can follow; a
  solution-wide grant is simply a grant on each of its projects.
- API keys cannot be restricted to a project: a key's restriction stays one repository or one image.

## What a reader sees

The solutions tree is readable by every account, and shows only what that account may see:

- A **project appears** when the reader holds a grant on it or sees at least one of its
  repositories. It lists only the repositories the reader may see.
- A project the reader sees only in part — say, one repository granted out of three — is marked
  **partial**, and its figures cover only what the reader sees. A partial grant sees a partial
  project, and says so, rather than presenting half a project as the whole of it.
- A **solution appears** when one of its projects does, and is partial when any repository filed
  under it is hidden from the reader.
- Administrators, CISOs and auditors see every solution and project, empty ones included.

Each project, each solution and the "no project" group carries its **open issues by severity**,
counted over the repositories the reader may see and leaving out settled triage (not affected,
fixed), like every other figure of risk.

## Deleting

- **Deleting a project** returns its repositories to "no project" and revokes every grant naming the
  project. It deletes **no repository and no finding**. The audit entry states how many repositories
  were detached and how many grants revoked.
- **Deleting a solution** is refused while it still holds a project: move its projects to another
  solution or delete them first, each one an audited decision of its own.

## The screen

**Solutions & projects**, in the sidebar next to **Repositories**, draws the tree for every account:
each solution, its projects, the repositories filed in each, then **No project** last — shown even
when it is empty. Every solution, project and the "no project" group carries its repository count
and one tag per severity that has open issues ("2 Critical", "1 High"), or "No open issues". A node
you see only in part carries **Partially visible: N repositories you can see**. A repository name
opens the issues of that repository.

On a solution or a project, **each severity tag is a link** to the [issues list](../guide/issues.md)
narrowed to that solution or project, that severity, and **Hide settled triage** — the clause the tag
counts by, so the list holds the number the tag showed. The tags of **No project** are figures only:
the list has no filter for "in no project".

Administrators also get:

| Action | Where | What the screen says first |
|---|---|---|
| **New solution** | top of the page | — |
| **New project** | on a solution | — |
| Rename or describe (pencil) | on a solution or a project | — |
| **Move to…** | on a project | that everything the project holds goes with it and nobody gains or loses sight of anything; the solution is chosen among the others, with an optional new name |
| Delete (bin) | on a solution or a project | for a project: its repositories return to "no project" and every grant naming it is revoked; for a solution: refused while it holds projects, with the server's reason shown |
| **File into project** | on a repository under "No project" | who gains sight of it: every account and team granted the project |
| Move (two arrows) | on a filed repository | who loses and who gains sight of it |
| Remove from project (cross) | on a filed repository | who loses sight of it |

When a project is moved to a solution already holding a project of the same name, the move dialog
stays open, says so, and takes a new name in the same dialog; once moved, the tree is redrawn and a
notice says where the project went.

The destination project is chosen from a list grouped by solution. Names are limited to 100
characters and descriptions to 255, in the form as on the server. Other accounts see the same tree
without any of these actions; the server would refuse them anyway.

The governance roles also get **Plugins** on each project: the registry with a switch per plugin,
live for administrators, the CISO and the governor, read-only for an auditor, each plugin's languages set against the project's (see
[Plugins and SARIF imports](plugins.md#the-languages-detected-in-a-repository)). A project whose
repositories have been counted shows the union of their languages as small tags beside its figures.

**Repositories** shows, on each repository, the project it is filed in — a link to that project in
the tree — or "—" when it is in none.

## Through the API

The same operations, for scripts:

| Route | Who | Does |
|---|---|---|
| `GET /api/v1/solutions` | any account | the tree, as far as the caller may see |
| `POST /api/v1/solutions` | administrator | create a solution (`name`, `description`); `409` of type `urn:vectispire:problem:solution-name-taken` when the name is taken |
| `PATCH /api/v1/solutions/{id}` | administrator | rename or describe it; an absent field is kept; `409` of type `urn:vectispire:problem:solution-name-taken` when the name is taken |
| `DELETE /api/v1/solutions/{id}` | administrator | delete it; `409` while it holds projects |
| `POST /api/v1/solutions/{id}/projects` | administrator | create a project in it; `409` of type `urn:vectispire:problem:project-name-taken` when the solution holds the name |
| `PATCH /api/v1/projects/{id}` | administrator | rename or describe a project, or move it: `solutionId`; `409` with the type `urn:vectispire:problem:project-name-taken` when the solution it ends up in holds its name — renamed, moved or both — `404` for a solution that does not exist |
| `DELETE /api/v1/projects/{id}` | administrator | delete a project, as described above |
| `PUT /api/v1/projects/{id}/repositories/{repositoryId}` | administrator | file or move a repository |
| `DELETE /api/v1/projects/{id}/repositories/{repositoryId}` | administrator | back to "no project" |

`GET /api/v1/repositories` also says which project each repository is in (`projectId`,
`projectName`).

## Related

- [Users and teams](users-and-teams.md) — granting a project to an account or a team.
- [Audit log](audit-log.md) — where creations, deletions and moves are recorded.
- [Security checklists](../guide/security-checklists.md) — a project's checklist, shown only to whoever sees the project whole.
