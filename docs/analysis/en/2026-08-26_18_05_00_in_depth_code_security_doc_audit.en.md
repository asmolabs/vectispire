# In-Depth Audit Report: Documentation, Source Code & Security

* **Project:** Vectispire — ASPM & Software Security Control Plane
* **Date:** 26 August 2026, 18:05
* **Commit audited:** `a791f53f` (`develop`)
* **Scope:** the five axes of [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)

> **Twelfth pass, the third today.** The two before it probed authorization, cryptography, the cost
> of reads and the fingerprint contract. This one aims at the single axis twelve passes have named
> without ever executing: **the ADR-0007 rule, applied where the thing being lost is not a
> finding.**

---

## 0. What was executed

| command | result |
|---|---|
| `./gradlew check` | **green** |
| `./gradlew integrationTestAll --rerun-tasks` | **green on all three engines**, 2 min |
| `npx ng test --no-watch` | **23 files, 146 tests** |
| `npx playwright test` | **13 of 13** (run earlier today, real browser) |

---

## 1. Summary

| Domain | Score | What sets it |
|---|:---:|---|
| **Documentation & Architecture** | **9.2 / 10** | Bilingual parity checked down to section headings, not just filenames |
| **Security & Cryptography** | **8.8 / 10** | Unchanged from the eleventh: nothing new found, nothing new probed |
| **Code Quality** | **7.9 / 10** | **ADR-0007 is violated at ingestion, and the consequence is visible on screen** |
| **Regulatory & Standards** | **9.3 / 10** | One posture evaluator, six mappings |
| **Verification that runs** | **9.0 / 10** | The browser suite finally tests something; still no green nightly |

---

## 2. The finding: 🔴 D1 — a failed analyzer erases the contract inventory

ADR-0007 states the rule: **absent means "did not run", empty means "ran, found nothing"**. The
prompt has repeated it for twelve passes. `ScanIngestor` honours it for the SBOM, and says so out
loud three lines before breaking it:

```java
// Absent when the cataloguer did not run — and absent means the previous scan's inventory is
// left alone rather than replaced by nothing.
artifacts.sbom().ifPresent(sbom -> inventory.record(scan.getId(), sbom, graph));

apiInventory.ifPresent(service -> {
    if (artifacts.apiEndpoints().isPresent() || artifacts.apiContracts().isPresent()) {
        service.record(scan,
                artifacts.apiEndpoints().orElse(List.of()),    // ← absent becomes empty
                artifacts.apiContracts().orElse(List.of()));   // ←
    }
});
```

**The guard only covers the case where both are absent.** If the endpoint extractor ran and the
contract cataloguer failed, `record` receives `[]` for the contracts. And `record` starts by
deleting:

```java
apiEndpoints.deleteByRepositoryIdOrScanId(repoId, scanId);
apiContracts.deleteByRepositoryIdOrScanId(repoId, scanId);   // unconditional
if (endpoints != null && !endpoints.isEmpty()) { … }          // only non-empty is written back
```

**Every contract the repository had disappears because an analyzer fell over.**

### And the consequence is not a blank panel, it is a false verdict

`ShadowApiDiff` is correct — it is the input that lies to it:

```java
if (contracts == null || contracts.isEmpty()) {
    // No contracts declared: all code endpoints are considered undocumented / shadow
    return new ShadowApiDiff(List.of(), codeEndpoints, List.of());
}
```

So the attack-surface screen turns **entirely red**: every endpoint is flagged a shadow API. Not
because the system changed — because a cataloguer failed. That is the exact shape ADR-0007 exists
to forbid, in a place its own example does not reach.

### Why no test saw it

`ScanIngestorTest` covers the neighbouring case, and covers it well:

```java
ScanArtifacts artifacts = ScanArtifacts.builder()
        .apiEndpoints(List.of(endpoint))
        .apiContracts(List.of())        // explicitly empty — "ran, found nothing"
        .build(Duration.ZERO);
```

It pins the **correct** behaviour for an empty list, and never exercises the ambiguous case:
`apiContracts` **absent**. That is precisely how a defect of this family survives — the test beside
it looks like coverage.

### Proposed fix

Pass the `Optional`s through to `record`, and delete only what there is something to replace. An
absent analyzer must leave its half of the inventory alone, exactly as the SBOM does three lines
above.

---

## 3. Documentation — 9.2

Bilingual parity was checked on **filenames** in the tenth pass. This time on **content**: the five
Florat views carry the same number of section headings in French and English (8, 11, 7, 6, 11).
That is not proof of a faithful translation, and it is what a mechanical check can say — a
structural divergence would have shown up.

---

## 4. Verification — 9.0, up, and for a specific reason

The browser suite **finally tests something**. Before today every case navigated with `page.goto`
after signing in — and the token lives in memory, deliberately not in `localStorage`, so a full
navigation dropped it and bounced back to the sign-in screen. Four cases asserted only that a
`body` was visible, which is true there. All thirteen now pass, and each was mutation-tested.

What still caps it: **no nightly pipeline has gone green.**

---

## 5. Recommendations

| # | Action | How it was verified |
|---|---|---|
| 🔴 1 | Pass the `Optional`s through to `ApiInventoryService.record` and delete only what is replaced | **measured**: `record` deletes unconditionally, `ShadowApiDiff` reads "empty" as "nothing declared" |
| 🟡 2 | An ingestion test for `apiContracts` **absent** — not merely empty | measured: `ScanIngestorTest` covers only the empty case |
| 🟡 3 | Sweep the domain's other `Optional`s for the same confusion | argued: two sites found here, the family was not swept |
