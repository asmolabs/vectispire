# The GitHub Actions that never ran

These three files were this project's entire verification for most of its life, and **not one of
them ever executed**. The only remote was GitLab, which does not interpret `.github/workflows/`,
so every check they describe — the link check, the C4 drift check, 1250 unit tests, the images,
the engine campaign, the browser suites, the release signature — was asserted and never run. The
[audit of 25 August 2026](../../en/2026-08-25_ci_that_never_ran_audit.en.md) established it, and
`.gitlab-ci.yml` was written in answer.

## Why they are here and not under `.github/`

**Because a file under `.github/workflows/` is not a document, it is a trigger.** Their `on:`
clauses are `push`, `pull_request` and `schedule`. The moment this repository is pushed to GitHub
— a mirror, a migration, a fork by somebody curious — all three start, and all three fail: they
are weeks stale and describe a pipeline that has since been rewritten. The first thing a visitor
would see on a security product's page is a red badge.

Moving them is what makes them archives. Disabling them with `if: false` would have left three
workflows that look maintained and are not, which is the same kind of lie the audit was about.

## What they are still good for

They record what the checks *were*, and what was thought worth checking, before any of it was
executed. Read them beside `.gitlab-ci.yml` and the difference is instructive: the trap that took
the longest to find — a Docker daemon that does not share the job's filesystem — does not exist in
these files, because on GitHub's runners the daemon does share it. Neither version is wrong; they
are written for different machines.

**If this project moves to GitHub**, these are a starting point and not a resumption. Every job
would need reading against what `.gitlab-ci.yml` now does, which is not what these describe.
