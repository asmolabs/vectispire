import { createHash } from 'node:crypto';

/**
 * An uploaded Semgrep rule set: what is accepted, and what is deliberately not done to it.
 *
 * Zanshin bundles a single rule — the public sets are not redistributable
 * ([decision 0006](../../../../docs/architecture/decisions/0006-semgrep-rules-written-here.md)) —
 * so an operator's coverage has to arrive from outside. `ZANSHIN_SEMGREP_RULES_DIR` is one
 * way, and it has a hole this module exists to close: it is read **by the process that
 * scans**, so every remote agent needs the directory provisioned on its own filesystem, and
 * the control plane cannot check that it was. Two agents, one provisioned and one not, take
 * turns on the same target and the SAST backlog resolves and reappears with each turn —
 * silently, because the step *ran* both times.
 *
 * A rule set stored centrally and fetched by every executor makes them identical by
 * construction.
 *
 * ## Zanshin never parses these rules, and that is a security decision
 *
 * The obvious implementation reads each file's YAML to count rules and read their ids. It is
 * refused here for a specific reason: `js-yaml` is pinned by `@nestjs/swagger` at a version
 * carrying an exponential-time parse advisory, and that advisory is *accepted* on the
 * grounds — written down in
 * [03 — Security](../../../../docs/architecture/03-security.md) — that "the only YAML that
 * path produces is the OpenAPI document Zanshin generates itself: the exponential-time parse
 * needs hostile input, and there is none". That document names what would change the
 * decision: "some path in Zanshin starting to parse YAML from elsewhere". This would have
 * been that path.
 *
 * So the bytes are stored verbatim and handed to **Semgrep**, which has to understand them
 * anyway and does so inside a container with the network cut off, `cap_drop: ALL`, and
 * memory and PID caps. The rule counting and id extraction below are bounded regular
 * expressions over a size-capped input, used **only** to tell an operator what they are
 * about to do. Nothing in a scan's correctness depends on them being exhaustive.
 *
 * ## The filenames are ours
 *
 * Uploaded names are recorded for display and never used as paths. Files are written into
 * the workspace as `rule-0001.yaml`, `rule-0002.yaml`, … which removes path traversal as a
 * class rather than filtering for it: there is no attacker-controlled path to escape from.
 *
 * This is free because `--no-rewrite-rule-ids` is passed to Semgrep. Without that flag
 * Semgrep would prefix every `check_id` with the rule file's relative path, and renaming
 * files would rename every identifier — which enters an issue's fingerprint, so the whole
 * SAST backlog would resolve and be recreated, triage lost.
 */

/** One uploaded file, as the API receives it. */
export interface UploadedRuleFile {
    /** The operator's name for it. Recorded, displayed, never used as a path. */
    name: string;
    content: string;
}

/** A stored rule set's files, under the names Zanshin chose. */
export interface StoredRuleFile {
    /** `rule-0001.yaml`. Generated here, never taken from the upload. */
    path: string;
    /** The name the operator uploaded, kept so a rule can be traced back. */
    originalName: string;
    content: string;
}

export class InvalidRuleSetError extends Error {}

/**
 * Caps, all three of them load-bearing.
 *
 * The per-file and total limits bound what a bounded regex has to walk and what a request
 * body can carry. The file count bounds the workspace copy: `opengrep-rules` is a few
 * thousand files, so the limit is set above that rather than below it.
 */
export const MAX_FILES = 8_000;
export const MAX_FILE_BYTES = 512 * 1024;
export const MAX_TOTAL_BYTES = 32 * 1024 * 1024;

const YAML_NAME = /\.ya?ml$/i;

/**
 * Validates an upload and returns it under Zanshin's own filenames.
 *
 * Throws rather than filtering silently: an operator who uploaded forty files and got
 * thirty-eight stored would have coverage they believe they have and do not.
 */
export function acceptUpload(files: UploadedRuleFile[]): StoredRuleFile[] {
    if (files.length === 0) throw new InvalidRuleSetError('No file was uploaded.');
    if (files.length > MAX_FILES) {
        throw new InvalidRuleSetError(`Too many files: ${files.length}, the limit is ${MAX_FILES}.`);
    }

    let total = 0;
    const stored: StoredRuleFile[] = [];

    for (const [index, file] of files.entries()) {
        const name = (file.name ?? '').trim();
        if (!YAML_NAME.test(name)) {
            throw new InvalidRuleSetError(`"${name || '(unnamed)'}" is not a YAML file. Semgrep rules are .yaml or .yml.`);
        }

        const bytes = Buffer.byteLength(file.content ?? '', 'utf8');
        if (bytes === 0) throw new InvalidRuleSetError(`"${name}" is empty.`);
        if (bytes > MAX_FILE_BYTES) {
            throw new InvalidRuleSetError(`"${name}" is ${bytes} bytes, over the ${MAX_FILE_BYTES} limit for one file.`);
        }
        total += bytes;
        if (total > MAX_TOTAL_BYTES) {
            throw new InvalidRuleSetError(`The upload exceeds ${MAX_TOTAL_BYTES} bytes in total.`);
        }

        stored.push({
            // Numbered from one, zero-padded to four: the order is stable, and Semgrep
            // reads the whole directory regardless.
            path: `rule-${String(index + 1).padStart(4, '0')}.yaml`,
            originalName: name,
            content: file.content
        });
    }
    return stored;
}

/**
 * The rule ids a file declares, by pattern match rather than by parsing.
 *
 * **Advisory only.** A rule whose id is written in a form this does not match is still
 * shipped to Semgrep and still runs; it is only missing from the counts and from the impact
 * warning. That trade is the point: an exhaustive answer would require parsing YAML, which
 * this module refuses to do (see the header).
 *
 * Anchored per line and bounded by the file size cap, so there is no backtracking blow-up
 * to worry about.
 */
export function extractRuleIds(content: string): string[] {
    const ids: string[] = [];
    for (const line of content.split('\n')) {
        const match = /^\s*-?\s*id:\s*["']?([A-Za-z0-9._\-/]+)["']?\s*$/.exec(line);
        if (match) ids.push(match[1]);
    }
    return ids;
}

/** Every id in a rule set, deduplicated. */
export function ruleIdsOf(files: StoredRuleFile[]): Set<string> {
    const ids = new Set<string>();
    for (const file of files) for (const id of extractRuleIds(file.content)) ids.add(id);
    return ids;
}

/**
 * The identity an executor caches on.
 *
 * Computed over the content and the generated paths, in order — not over the upload's own
 * names, so re-uploading the same rules under different filenames does not invalidate every
 * agent's cache.
 */
export function hashRuleSet(files: StoredRuleFile[]): string {
    const hash = createHash('sha256');
    for (const file of files) {
        hash.update(file.path, 'utf8');
        hash.update('\0', 'utf8');
        hash.update(file.content, 'utf8');
        hash.update('\0', 'utf8');
    }
    return hash.digest('hex');
}

export interface TriageImpact {
    /** Rule ids that currently have open issues and are absent from the new set. */
    losingIssues: string[];
    /** How many open issues those ids account for. */
    affectedIssues: number;
    addedRules: number;
    removedRules: number;
}

/**
 * What activating a rule set would do to the existing backlog.
 *
 * **This is the part that needs saying out loud in the interface.** A rule id enters an
 * issue's fingerprint, so a rule that disappears takes its issues with it: the next scan
 * does not find them, and they are resolved — with their triage decisions, their
 * justifications, their review dates. A three-click upload makes that destruction reachable
 * by somebody who does not know it.
 *
 * Counted from the issues that are **open** right now, because a resolved issue has nothing
 * left to lose.
 */
export function triageImpact(current: Set<string>, next: Set<string>, openIssuesByRuleId: Map<string, number>): TriageImpact {
    const losingIssues: string[] = [];
    let affectedIssues = 0;

    for (const [ruleId, count] of openIssuesByRuleId) {
        if (next.has(ruleId)) continue;
        losingIssues.push(ruleId);
        affectedIssues += count;
    }

    let addedRules = 0;
    for (const id of next) if (!current.has(id)) addedRules += 1;
    let removedRules = 0;
    for (const id of current) if (!next.has(id)) removedRules += 1;

    // Sorted so the warning reads the same twice, and so a long list can be truncated
    // predictably by the screen showing it.
    losingIssues.sort();
    return { losingIssues, affectedIssues, addedRules, removedRules };
}
