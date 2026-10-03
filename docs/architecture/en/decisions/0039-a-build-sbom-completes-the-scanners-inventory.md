# 0039 — A build's SBOM completes the scanner's inventory: union, the build's stated version wins, the newest one for every later scan

**Date:** 2026-10-03 · **Status:** proposed · **Builds on:** [0007](0007-none-is-not-an-empty-list.md), [0017](0017-custom-checks-as-container-images.md), [0032](0032-security-checklists.md), [0033](0033-internal-reactions-leave-through-the-outbox.md), [0035](0035-report-plugins.md) · **Decider:** Laurent Boucher

*Proposed with lot G10, which implements it as written; the precedence below is the one the code
applies, and the questions at the end are the reviewer's to settle.*

## Context

Every inventory Vectispire holds of a repository is the scanner's: Syft reads the source tree and
lists what its manifests declare. For a Maven tree that is not enough, in two ways that each produce
a false answer:

- **A version managed by a parent or a BOM is `UNKNOWN`.** Syft does not resolve an imported BOM, so
  `spring-core` declared without a version under `spring-framework-bom` comes out as
  `"version": "UNKNOWN"` with a purl that carries no version. A checklist `component_versions` line
  then has no data for it (`version_unrecorded`, [0032](0032-security-checklists.md) §6).
- **A library pulled in transitively is not listed at all.** The poms declare `spring-core`; the
  build packages `spring-jcl` with it. A line asking "is `snakeyaml` used, and at which version" is
  answered *not in its SBOM* — a **false "no"**, which the automatic answers ([0032](0032-security-checklists.md),
  amendment "the scans answer the lines they measure") write into a checklist as "no".

The build knows the resolved graph: `cyclonedx-maven-plugin`'s `makeAggregateBom` and the Gradle
CycloneDX plugin write it as CycloneDX JSON. Vectispire already admits a pipeline's documents through
declared sources ([0017](0017-custom-checks-as-container-images.md) §7, [0032](0032-security-checklists.md) §7):
SARIF, coverage, test reports. The question is not how to receive the build's SBOM — the same door —
but what it means beside the scanner's, and for which readers.

## Decision

### 1. Received as a report: a fourth kind, `sbom`

`POST /api/v1/repositories/{id}/build-sbom-imports`, through `ReportImportService` and the same
steps as coverage: an integration key, never a session; a key declared as an enabled source whose
kinds include `sbom` (scope `report_import` — it opens no issue); a repository the key sees inside
the source's scope (404 otherwise, in an absence's words); a body under
`vectispire.http.max-body.sbom-import` (32 MB). Each refusal of what the caller claims is audited
`REPORT_IMPORT_REFUSED` and signalled `VECTI-SEC-027`; an accepted one is `BUILD_SBOM_IMPORTED`,
after the commit, with the document's SHA-256 and the scan it completed. `commit` and `branch` are
the pipeline's word.

The document is read by `BuildSbom`: `bomFormat` `CycloneDX`, `specVersion` 1.4, 1.5 or 1.6, JSON
only; nesting, strings and numbers bounded, a duplicate key refused, content after the end refused;
at most 50,000 components, nested ones included; a value wider than its column refused, never cut.
**Nothing is fetched**: `externalReferences`, a `bom-link`, a `$schema` are never followed. A document
without `components` is refused — it listed nothing it can be held to — and an empty array is a build
with no dependency ([0007](0007-none-is-not-an-empty-list.md)).

### 2. Kept by the inventory, with its components

`inventory` keeps the import (`t_build_sbom`) and its components (`t_build_sbom_component`), not only
a figure: every later scan is completed by it. The governance — the source, the key, the audit —
stays `plugins`'; `plugins` gains `inventory` in its list for this, and the dependency points one way.

### 3. The precedence: the scanner's inventory, completed by the newest build SBOM

**A scan's inventory is what its scanner listed, completed by the newest build SBOM of its repository
that states the scan's branch or no branch.** The completion (`InventoryCompletion`):

1. **Union.** Every component the scanner listed stays; every component the build lists that the
   scanner does not is added. The scanner sees what no build declares — a front end beside the Maven
   tree, a vendored file — and the build sees what the scanner cannot.
2. **One package, matched by its purl** without version, qualifiers or subpath. The Maven plugin's
   default `type=jar` qualifier is dropped on reading, so `pkg:maven/g/a@1.0?type=jar` and Syft's
   `pkg:maven/g/a@1.0` are one package; any other qualifier stays. A scanner row with no purl matches
   nothing — a name is not an identity across ecosystems.
3. **The build's stated version wins** where both list a package, whatever the scanner wrote:
   `UNKNOWN`, nothing, or a version read off a manifest. The build resolved the graph and packaged
   what it states. A build that states no version leaves the scanner's.
4. **Several versions of one package in the build** complete a scanner row with the one at its own
   version, else the first listed; the others are added. Nothing the build stated is dropped.

**When it applies.** Twice: when a scan's inventory is written (the ingestion's sink, in its
transaction), and when an SBOM arrives — the repository's newest completed scan holding an SBOM is
completed again in the import's transaction, which also queues the checklists' reaction through the
outbox ([0033](0033-internal-reactions-leave-through-the-outbox.md)), so every
reader sees it as soon as the import is answered. A newer SBOM replaces an older one's completion:
what the older one added goes, and a row it completed gets the scanner's version and purl back
(`scanned_version`, `scanned_purl`).

**Older scans keep what they were given.** A scan's inventory is history: only the newest scan moves
on an import. **A scan that kept no inventory is not completed** — its SBOM step failed, or the
payload retention purged the SBOM before it was indexed: the build's word completes a scanner's
inventory, it does not stand in for a scan that did not look. A scan whose payload was purged *after*
its inventory was written keeps the scanner's rows, which the component rules read, and is completed.

**Provenance on every row.** `t_component.origin` is null for the scanner (every row written before
V82 and every row a scan writes), `build` for a component only the build listed, `both` for a
scanner row the build also lists — the version and purl then the build's, the scanner's kept beside
them. `declared_license` holds the licence the build declared; `build_sbom_id` names the import, as a
reference only.

### 4. What reads it, and how

The completed rows *are* the inventory: no reader chooses between two sources, so none can disagree
with another.

| Reader | What it reads after this |
|---|---|
| The component search, `GET /api/v1/inventory/search` | the rows of every scan, each with `source` (`scanner`, `build`, `both`) and, for `both`, `scannerVersion` |
| The project's consolidated inventory and its CycloneDX export | the newest completed scan of each target, completed; each merged component with `sources` |
| The project export ([0035](0035-report-plugins.md) §1) | the same, `inventory.components[].sources` — an optional field, schema **1.1** |
| The checklist rules `component_versions` and `component_present` | the components of each repository's newest scan in which the dependency step produced (`ComponentCatalog.componentsOf`, the one read both rules share), **completed by the newest build SBOM of that scan's branch**: the build's versions in place of `UNKNOWN`, the transitive libraries present. Which scan they read does not change, nor what they answer when it kept no inventory (`inventory_absent`); a build SBOM alone is not a scan |
| The licence inventory and its tallies | the scanner's SBOM and the component rows, as before; a completed row replaces the entry the scanner's SBOM gave under its own version, with the build's declared licence (else the scanner's). The tallies' stamp counts the build-completed rows and the newest import among them, so an SBOM arriving recounts them with no scan moving |
| The SBOM diff between two scans | the two scans' rows, completed as each was |
| Vulnerability matching | **unchanged**: Grype runs inside the scan on the scanner's SBOM. A build SBOM opens and resolves no issue |

### 5. Retention and deletion

The imports and their components leave by the **evidence window** (`evidence_retention_days`,
`BuildSbomRetentionTask`), zero purging none. The rows a scan was completed with stay with the scan:
an inventory is what it was given. A repository whose pipeline stopped sending SBOMs therefore reads
the scanner alone on its next scans once the last SBOM is past the window. A repository's imports go
with it (`TargetDeleted`, first phase); the scans' completed rows go with the scans.

## Rejected

- **The build's SBOM only when it is newer than the scan.** It reads as the safer rule and is the
  more surprising one: a scheduled scan of an unchanged tree runs after the last push, so every quiet
  week would bring the false "no" back until somebody pushed. Scans record no commit to compare with.
- **The build's SBOM instead of the scanner's.** It drops what only the scanner sees — the npm tree
  beside the Maven one, the vendored binaries — and makes a pipeline that forgets a module the
  authority on the whole repository.
- **A merge computed by each reader.** Six readers, six chances to disagree: the inventory, the
  licences and the checklist would have answered three questions about one tree. Materialised once,
  they read the same rows.
- **A build version only where the scanner's is `UNKNOWN`.** Syft reads a declared `1.0` where Maven's
  mediation packaged `1.1`; keeping the scanner's would keep the wrong one. Where the build states a
  version, it is the packaged one.
- **Grype on the build SBOM.** Worth doing, and not here: matching runs in the scan's closed shape on
  the executor, and a second matcher outside it is a decision of its own.

## Consequences

- The false "no" of a `component_versions` or `component_present` line is gone for a repository whose
  pipeline sends its SBOM, and `version_unrecorded` with it, as soon as the import is answered — the
  remedy that rule's evidence names ("import an SBOM produced by the build").
- A stale build SBOM — a pipeline that stopped sending one — keeps completing scans until the evidence
  window removes it. Its import date is on every row's history and in the audit log.
- Two imports completing one scan at the same instant are serialised by a lock on the scan's rows; a
  scan whose scanner listed nothing has no row to lock, and two such imports may both add their
  components — the next import or scan of the repository rewrites them.
- The project export moves to **1.1**: an optional field, by the schema's own rule.

## Open questions

1. Should a build SBOM older than the evidence window — or older than a set age — stop completing
   scans before it is purged?
2. Should the scope (`required`, `optional`, `excluded`) of a CycloneDX component exclude it from the
   checklist's reading? Today every listed component counts, as Syft's test-scope dependencies do.
