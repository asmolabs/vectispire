/**
 * Which agent is allowed to run which scan.
 *
 * **The queue was routed by no criterion at all.** Any registered agent claimed any scan,
 * and whoever asked first was served. An agent placed in a less-trusted segment — because
 * it has to reach a repository there, which is precisely why remote agents exist — could
 * therefore claim every other repository's scans, and receive their deployment keys with
 * them.
 *
 * Neither end-to-end sealing nor `local` mode closes this: the first protects the key *in
 * transit* and does open it at the claimant, the second removes the key but still lets the
 * agent read the source code. The only answer is to say **where** a scan is allowed to go.
 *
 * **A label, not a list of agents.** Naming agents would make every machine replacement a
 * change to every repository it serves; a label describes a *capability* — "reaches the
 * production network", "cleared for customer repositories" — and a new agent carries it
 * from the moment it registers.
 *
 * **Closed by default on the agent's side, open on the scan's side.** A scan with no
 * requirement goes to anyone: that is the previous behaviour, and imposing otherwise
 * retroactively would stop every existing queue on the first deployment. An agent with no
 * label, on the other hand, only takes work with no requirement — it does not "match
 * everything".
 */

/** Separator for an agent's labels, as the operator types them. */
const SEPARATOR = ',';

/**
 * An agent's labels, normalized.
 *
 * Whitespace stripped and case lowered: "Production" and "production" typed six months
 * apart on two different screens must mean the same thing, otherwise a scan would wait
 * indefinitely for an agent that is right there.
 */
export function parseAgentLabels(raw: string | null | undefined): string[] {
    if (typeof raw !== 'string') return [];
    return [...new Set(raw.split(SEPARATOR).map(normalizeLabel).filter((label) => label !== ''))];
}

/**
 * A target's requirement, normalized — or `null` for "none".
 *
 * The empty string becomes `null` deliberately: a form field that has been cleared means
 * "no requirement any more", and storing it as is would give a requirement nothing ever
 * satisfies.
 */
export function normalizeRequiredLabel(raw: string | null | undefined): string | null {
    if (typeof raw !== 'string') return null;
    const label = normalizeLabel(raw);
    return label === '' ? null : label;
}

/**
 * Can this agent run a scan carrying this requirement?
 *
 * Kept apart from the SQL query because the same decision is then checkable on both sides:
 * the queue filters in the database, and the dispatcher can confirm it on the row it
 * actually took. A rule written once, in SQL, would have been re-argued at every review.
 */
export function agentAccepts(agentLabels: string[], required: string | null): boolean {
    if (required === null) return true;
    return agentLabels.includes(required);
}

function normalizeLabel(raw: string): string {
    return raw.trim().toLowerCase();
}
