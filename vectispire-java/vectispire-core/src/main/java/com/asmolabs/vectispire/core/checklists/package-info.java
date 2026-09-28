/**
 * Security checklists — the organisation's templates, their versions and their items, imported from
 * its own workbooks (decision 0032). The project checklists answered against them, their evidence and
 * their measurements are later lots of the same module.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared — the audit log, the settings (four-eyes on
 * publishing) — so the list names only what the lots so far use. Decision 0032 §1 tabulates what the
 * later lots will add, each with its reason: {@code targets}, {@code scanning}, {@code issues},
 * {@code plugins}, {@code inventory}, and {@code access} for the whole-project guard. Each is added by
 * the lot that first uses it, in its review, not ahead of it.
 *
 * <p>Nothing yet: the tables and their mappings come first, the routes with their markers next.
 */
@ApplicationModule(allowedDependencies = {})
package com.asmolabs.vectispire.core.checklists;

import org.springframework.modulith.ApplicationModule;
