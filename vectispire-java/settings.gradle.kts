rootProject.name = "vectispire"

/**
 * Three modules, and the reason there are three rather than one.
 *
 * ```
 *   vectispire-core  ──┐
 *                      ├──►  vectispire-common  (domain calculations + scan execution)
 *   vectispire-agent ──┘
 * ```
 *
 * And a fourth that is not part of the product: `vectispire-report-demo`, the demonstration report
 * plugin (decision 0035 §6). It depends on none of the three — a plugin knows the export's schema, not
 * the platform — and ships as an image of its own.
 */
include(
    "vectispire-common",
    "vectispire-core",
    "vectispire-agent",
    "vectispire-report-demo",
)
