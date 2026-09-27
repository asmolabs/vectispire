package com.asmolabs.vectispire.core.targets;

/**
 * A project is being deleted, in the transaction that deletes it.
 *
 * <p>The {@link TargetDeleted} pattern for a project: {@code targets} publishes it, and a module above
 * that keeps rows naming the project — the plugins activated for it, the SARIF sources scoped to it —
 * removes its own in a listener that requires this transaction. Left behind, those rows would name a
 * project nobody can see; and should an engine ever hand the identifier out again, they would switch
 * a plugin on for, or let a key import into, a project nobody chose — the same reason the grants go.
 *
 * <p>No foreign key follows these rows: the tables are written once, in common migrations, and a key
 * would have to be written three times (decision 0027).
 */
public record ProjectDeleted(long projectId) {}
