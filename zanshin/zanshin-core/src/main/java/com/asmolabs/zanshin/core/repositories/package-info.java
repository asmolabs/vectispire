/**
 * The queries, and nothing else.
 *
 * <p>One file per aggregate. They were once one {@code Repositories} class holding thirteen
 * three-line interfaces, on the argument that thirteen tiny files make "which queries exist" a
 * directory listing. Several of them then grew past fifty lines and the argument stopped being
 * true — a comment defending a shape the file no longer has is worse than no comment.
 *
 * <h2>Two conventions, both load-bearing</h2>
 *
 * <b>Every write carries {@code @Transactional}</b> — the {@code @Modifying} queries and the
 * derived {@code deleteBy…} methods alike. The derived ones are the trap: they have no
 * annotation to prompt the question, and they fail at runtime with "No EntityManager with actual
 * transaction available" rather than at startup. Spring Data makes
 * derived and inherited methods transactional but not custom modifying queries, so one written
 * without it fails outright when no caller happens to have opened a transaction — and works
 * when one has, which is how the omission survives review and reaches production as an
 * intermittent failure.
 *
 * <p><b>Writes that must arbitrate are conditional statements, never {@code save}.</b> Claiming
 * a scan, taking a leader lease, superseding a rule set: in each case the affected row count is
 * what names the winner. A {@code save} reads then writes, and the winner becomes whoever wrote
 * last rather than whoever met the condition.
 */
package com.asmolabs.zanshin.core.repositories;
