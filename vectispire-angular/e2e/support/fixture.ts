import { DatabaseSync } from 'node:sqlite';

/**
 * A real finding in the browser suite's database.
 *
 * <p><b>Without it, two cases in `roles.spec.ts` could not fail.</b> They assert that an auditor is
 * offered no triage button, and the suite's database never held a single vulnerability: the list
 * rendered empty, the button count was zero for everybody, and the assertion passed just as well
 * with the guard as without it. The same defect as the two `body` assertions in the audit file,
 * written the other way round.
 *
 * <p><b>Written in SQL, not through a route.</b> A vulnerability is born of a scan reported by an
 * agent; manufacturing it by the real path would take an agent key and a complete result payload
 * to obtain a row whose existence is all that matters here. What these cases test is the agreement
 * between the role and the screen, not ingestion.
 */
/**
 * Gives the brute-force counter its attempt budget back.
 *
 * <p><b>The campaign shared a security control, and fought itself over it.</b>
 * {@code LoginThrottle} blocks after five failures per account and twenty per client over a
 * fifteen-minute sliding window, and those are compile-time constants. The variable the nightly
 * sets to 200 raises {@code LoginRateLimitFilter}'s per-address bucket — a real counter, but a
 * different one: it does not touch this. Seventeen cases signing in therefore spend that budget,
 * and the case that receives the {@code 429} is not the one that spent it: the failures landed
 * according to execution order, on unrelated suites.
 *
 * <p><b>Reset the counter rather than weaken the threshold.</b> An authentication threshold the
 * environment can raise is a weakening switch shipped with the product; the campaign's database,
 * by contrast, belongs to the campaign. `auth.spec.ts` tests precisely this control, and this call
 * gives it a clean budget per case instead of taking the control away from it.
 */
export function resetLoginThrottle(): void {
    withDatabase((db) => db.prepare('delete from t_login_attempt').run());
}

/** The one place that knows where the campaign's database lives, and that closes it. */
function withDatabase<T>(work: (db: DatabaseSync) => T): T {
    const url = process.env.VECTISPIRE_DB_URL ?? 'jdbc:sqlite:/tmp/e2e.db';
    const file = url.replace(/^jdbc:sqlite:/, '');

    // **Loud rather than silent.** Giving up without a word would hand the cases back the
    // emptiness these functions exist to take away: they would go green while testing nothing.
    if (url === file) {
        throw new Error(`VECTISPIRE_DB_URL n'est pas une base SQLite : ${url}`);
    }

    const db = new DatabaseSync(file);
    try {
        return work(db);
    } finally {
        db.close();
    }
}

export function seedOneIssue(): void {
    withDatabase((db) => {
        const seen = db.prepare('select count(*) as n from t_issue').get() as { n: number };
        if (seen.n > 0) return;

        db.prepare(
            `insert into t_repository (url, branch, name) values (?, ?, ?)`
        ).run('https://example.invalid/seed.git', 'main', 'seed repository');
        const repo = db.prepare('select last_insert_rowid() as id').get() as { id: number };

        const now = Date.now();
        db.prepare(
            `insert into t_issue (repo_id, fingerprint, type, identifier, package_name,
                                  package_version, severity, cvss_score, state,
                                  first_seen_at, last_seen_at, description, fix_versions)
             -- The fix versions are out of order, and "2.9.0" sorts after "2.17.1" in a string
             -- comparison: that is exactly what the plan must not advise.
             values (?, ?, 'vulnerability', 'CVE-2021-44228', 'log4j-core',
                     '2.14.1', 'critical', 10.0, 'open', ?, ?, ?, '2.9.0, 2.17.1, 2.12.4')`
        ).run(repo.id, 'seed-fingerprint-0000', now, now,
              'Seeded finding: the list needs a row for the absence of a button to mean anything.');
    });
}
