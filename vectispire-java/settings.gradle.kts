rootProject.name = "vectispire"

/**
 * Three modules, and the reason there are three rather than one.
 *
 * ```
 *   vectispire-core  ──┐
 *                      ├──►  vectispire-common  (domain calculations + scan execution)
 *   vectispire-agent ──┘
 * ```
 */
include(
    "vectispire-common",
    "vectispire-core",
    "vectispire-agent",
)
