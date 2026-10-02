import { createConnection, type Connection, type ResultSetHeader, type RowDataPacket } from 'mysql2/promise';

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
export async function resetLoginThrottle(): Promise<void> {
    await withDatabase((db) => db.execute('delete from t_login_attempt'));
}

/**
 * The one place that knows where the campaign's database lives, and that closes it.
 *
 * <p><b>Read from the control plane's own variables</b> — `VECTISPIRE_DB_URL`, `VECTISPIRE_DB_USER`,
 * `VECTISPIRE_DB_PASSWORD` — with the control plane's own defaults (`application.yaml`). The job
 * sets them once for both processes, so the helpers cannot write to one database while the server
 * reads another: a second set of variables would be a second place to get the address wrong.
 */
async function withDatabase<T>(work: (db: Connection) => Promise<T>): Promise<T> {
    const url = process.env['VECTISPIRE_DB_URL'] ?? 'jdbc:mysql://localhost:3306/vectispire';
    const parts = /^jdbc:mysql:\/\/([^/:?]+)(?::(\d+))?\/([^?]+)/.exec(url);

    // **Loud rather than silent.** Giving up without a word would hand the cases back the
    // emptiness these functions exist to take away: they would go green while testing nothing.
    if (!parts) {
        throw new Error(`VECTISPIRE_DB_URL is not a MySQL database: ${url}`);
    }

    const db = await createConnection({
        host: parts[1],
        port: parts[2] ? Number(parts[2]) : 3306,
        database: parts[3],
        user: process.env['VECTISPIRE_DB_USER'] ?? 'vectispire',
        password: process.env['VECTISPIRE_DB_PASSWORD'] ?? '',
        // The control plane stores instants in UTC; a `Date` written in the runner's zone would
        // put the seeded finding hours away from where the screens expect it.
        timezone: 'Z'
    });
    try {
        return await work(db);
    } finally {
        await db.end();
    }
}

export async function seedOneIssue(): Promise<void> {
    await withDatabase(async (db) => {
        const [seen] = await db.query<RowDataPacket[]>('select count(*) as n from t_issue');
        if (Number(seen[0]['n']) > 0) return;

        const [repo] = await db.execute<ResultSetHeader>(
            `insert into t_repository (url, branch, name) values (?, ?, ?)`,
            ['https://example.invalid/seed.git', 'main', 'seed repository']
        );

        const now = new Date();
        await db.execute(
            `insert into t_issue (repo_id, fingerprint, type, identifier, package_name,
                                  package_version, severity, cvss_score, state,
                                  first_seen_at, last_seen_at, description, fix_versions)
             -- The fix versions are out of order, and "2.9.0" sorts after "2.17.1" in a string
             -- comparison: that is exactly what the plan must not advise.
             values (?, ?, 'vulnerability', 'CVE-2021-44228', 'log4j-core',
                     '2.14.1', 'critical', 10.0, 'open', ?, ?, ?, '2.9.0, 2.17.1, 2.12.4')`,
            [repo.insertId, 'seed-fingerprint-0000', now, now,
             'Seeded finding: the list needs a row for the absence of a button to mean anything.']
        );
    });
}
