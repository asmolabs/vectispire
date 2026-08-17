import { cp, mkdir, stat, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import type { Workspace } from './workspace';

/**
 * The rules Zanshin places into a scan's workspace.
 *
 * **Why copy rather than mount the original directory.** Volume paths are resolved by the
 * Docker *daemon*, not by the process calling it: when Zanshin itself runs in a container
 * with the socket mounted, a directory from its image is invisible to the sibling
 * container. The workspace is the only path both sides see, locally as on a remote agent.
 *
 * **Why this is a module of its own and not a private method of the runner.** Two scanners
 * depend on it — Semgrep for its rules, gitleaks for its configuration — and the
 * integration tests exercise them one at a time, without going through the runner. A
 * private method would have left the tests rebuilding this placement by hand, hence
 * diverging from the real path the day it changes.
 */

/** The bundled tree, next to this module — `semgrep/` and `gitleaks/`. */
const BUNDLED_RULES = join(__dirname, 'rules');

/** Where the operator's rules land inside the workspace. */
const OPERATOR_SUBDIR = 'operator';

/** The operator declared a rules directory and it cannot be used. */
export class OperatorRulesUnavailable extends Error {}

/**
 * Copies the bundled tree into `workspace.rules`.
 *
 * Called **before any scanner**, and not from the step with the most obvious use for it:
 * gitleaks' configuration has to be in place even when SAST is off, otherwise the tool
 * falls back to the scanned repository's `.gitleaks.toml` — that is, the target supplies
 * the rules of its own audit.
 */
export async function placeBundledRules(workspace: Workspace): Promise<void> {
    await cp(BUNDLED_RULES, workspace.rules, { recursive: true });
}

/**
 * Merges the operator's rule directory into the workspace, if one is configured.
 *
 * `ZANSHIN_SEMGREP_RULES_DIR` is the second of the three sources decision 0006 describes,
 * and the one the whole licensing argument rests on: Zanshin ships only rules it wrote,
 * so an operator's own coverage can only arrive this way. It was documented in the README
 * and in the settings table, and **read nowhere** — a scan ran with the bundled rules
 * alone, and nothing said so.
 *
 * ## Placed in a subdirectory, not merged file by file
 *
 * Semgrep is pointed at the `semgrep/` directory and walks it, so a subtree is enough for
 * the rules to be loaded. Keeping them apart means an operator file can never silently
 * overwrite a bundled one by sharing its name.
 *
 * Placement is free here **only because `--no-rewrite-rule-ids` is passed**: without it,
 * Semgrep would prefix every `check_id` with the rule file's relative path, so moving
 * rules between directories would rename every identifier — and the identifier enters an
 * issue's fingerprint, which would resolve the entire SAST backlog and recreate it as new,
 * triage lost. If that flag is ever dropped, this subdirectory becomes a data migration.
 *
 * ## Failing is the point
 *
 * A configured directory that cannot be read **throws**, rather than letting the scan run
 * with the bundled rules alone. The caller places this inside the SAST step, so the
 * failure leaves `sast` at `null` — "did not run" — and the backlog is left intact.
 *
 * Running anyway would be the dangerous outcome: Semgrep would exit cleanly with fewer
 * findings, which reads as "analyzed, those issues are gone" and **resolves every finding
 * the operator's rules had produced**. Silently, on every target, the first time a volume
 * is forgotten in a deployment.
 */
export async function placeOperatorRules(workspace: Workspace, directory = process.env.ZANSHIN_SEMGREP_RULES_DIR): Promise<boolean> {
    const configured = (directory ?? '').trim();
    if (!configured) return false;

    try {
        const entry = await stat(configured);
        if (!entry.isDirectory()) {
            throw new OperatorRulesUnavailable(`ZANSHIN_SEMGREP_RULES_DIR points at ${configured}, which is not a directory.`);
        }
    } catch (error) {
        if (error instanceof OperatorRulesUnavailable) throw error;
        throw new OperatorRulesUnavailable(`ZANSHIN_SEMGREP_RULES_DIR points at ${configured}, which cannot be read: ${(error as Error).message}`);
    }

    await cp(configured, join(workspace.rules, 'semgrep', OPERATOR_SUBDIR), { recursive: true });
    return true;
}

/** What an executor calls to obtain a rule set it does not hold. */
export type RuleSetProvider = (contentHash: string) => Promise<{ path: string; content: string }[]>;

/**
 * Places the rule set a task names, and says whether it did.
 *
 * ## The precedence, and why it is exclusive
 *
 * An uploaded set **replaces** `ZANSHIN_SEMGREP_RULES_DIR` rather than merging with it.
 * Merging is the friendlier-looking choice and it reintroduces the exact defect the upload
 * exists to remove: the directory is per-executor, so a merged result differs between an
 * agent that has it and one that does not, and the SAST backlog resolves and reappears as
 * the two take turns. One authoritative source per scan is the property worth having.
 *
 * With no set active, the directory still applies — it remains the right answer for a
 * single-instance deployment that already manages a volume, and withdrawing it would break
 * those.
 *
 * ## Failing is the point, again
 *
 * A task naming a rule set whose content the executor cannot obtain **throws**. Running
 * with the bundled rule instead would exit cleanly with a shorter list, which reads as
 * "analyzed, those issues are gone" — resolving everything the operator's rules had found.
 * The caller places this inside the SAST step, so the failure leaves `sast` at `null`.
 */
export async function placeRuleSet(
    workspace: Workspace,
    contentHash: string | null | undefined,
    provider: RuleSetProvider | null | undefined
): Promise<boolean> {
    if (!contentHash) return placeOperatorRules(workspace);

    if (!provider) {
        throw new OperatorRulesUnavailable(
            `This scan requires uploaded rule set ${contentHash}, and this executor has no way to fetch it.`
        );
    }

    let files: { path: string; content: string }[];
    try {
        files = await provider(contentHash);
    } catch (error) {
        throw new OperatorRulesUnavailable(`Rule set ${contentHash} could not be fetched: ${(error as Error).message}`);
    }
    if (files.length === 0) {
        throw new OperatorRulesUnavailable(`Rule set ${contentHash} came back empty; refusing to scan with the bundled rules alone.`);
    }

    const directory = join(workspace.rules, 'semgrep', OPERATOR_SUBDIR);
    await mkdir(directory, { recursive: true });
    for (const file of files) {
        // `basename`, not the path as given: the paths are generated by Zanshin, but this
        // content arrives over HTTP on an agent, and a guard that costs one call is worth
        // more than the argument that it cannot be hostile.
        await writeFile(join(directory, basename(file.path)), file.content, 'utf8');
    }
    return true;
}
