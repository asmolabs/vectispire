rootProject.name = "veriscape"

/**
 * Three modules, and the reason there are three rather than one.
 *
 * ```
 *   veriscape-core  ──┐
 *                     ├──►  veriscape-common  (domain calculations + scan execution)
 *   veriscape-agent ──┘
 * ```
 */
include(
    "veriscape-common",
    "veriscape-core",
    "veriscape-agent",
)
