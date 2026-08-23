rootProject.name = "zanshin"

/**
 * Three modules, and the reason there are three rather than one.
 *
 * ```
 *   zanshin-core  ──┐
 *                   ├──►  zanshin-common  (domain calculations + scan execution)
 *   zanshin-agent ──┘
 * ```
 *
 * `zanshin-common` holds what both sides must agree on: the calculations that *decide*
 * (issue fingerprint, gate verdict, audit chain, export formats) and the scan execution
 * that produces the artifacts. `zanshin-core` is the control plane — schema, repositories,
 * use cases, HTTP. `zanshin-agent` is the remote runner.
 *
 * **The split is a security boundary, not packaging.** `zanshin-agent` does not depend on
 * `zanshin-core`, so no JDBC driver, no Hibernate and no Spring Data is on its compile
 * classpath. An agent holding a database connection would also need `ENCRYPTION_KEY`, which
 * is enough to decrypt *every* deployment key Zanshin holds; the property that justifies the
 * agent's existence is precisely what it does not have (decision 0003). In the NestJS tree
 * that was asserted by a test reading the import graph. Here it is a build-graph fact: the
 * violation does not fail review, it fails to compile.
 *
 * The layers *inside* `zanshin-core` — persistence, repositories, services, api — are
 * enforced by the ArchUnit suite instead, since one module cannot express them. That is the
 * cost of three modules over nine, and it is a real one: an ArchUnit rule can be deleted by
 * the same commit that violates it, a missing dependency cannot.
 */
include(
    "zanshin-common",
    "zanshin-core",
    "zanshin-agent",
)
