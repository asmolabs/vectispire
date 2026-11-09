/**
 * What other modules hand {@code issues}' queries and read back from them, as they are: {@code
 * IssueFilters} (the criteria, visibility included, that every read over the backlog applies), {@code
 * IssueRows} (the narrow reads the gate, the scorecards, the attack paths, the compliance evidence
 * and the EPSS ranking take instead of whole issues) and {@code IssueAggregates} (the grouped counts
 * of the dashboards, the debt report and the OWASP grid).
 *
 * <p><b>The criteria are here, not at the module's root,</b> because the predicate built from them —
 * {@code IssueSpecifications} — belongs beside the repository that runs it, and {@code persistence}
 * reaches nothing above it. The record names no entity and no JPA type; the translation does.
 *
 * <p><b>Published, read-only, and nothing else of {@code persistence}.</b> They are records the
 * database fills and {@code IssueCatalog} hands over unchanged; restating each as an API record would
 * be a second copy to keep in step with its query for no reader's benefit. The entities, the
 * repositories and the aggregation fragment stay the module's own: another module asks {@code
 * IssueCatalog}, with {@code IssueFilters}, never a repository or a {@code Specification} (decision
 * 0029). A controller may not name these either — {@code apiNeverTouchesPersistence} holds for every
 * {@code persistence} package, this one included.
 */
@NamedInterface("queries")
package com.asmolabs.vectispire.core.issues.persistence.queries;

import org.springframework.modulith.NamedInterface;
