import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { OperatorRulesUnavailable, placeBundledRules, placeOperatorRules } from './bundled-rules';
import { RULES_SUBDIR, type Workspace } from './workspace';

/**
 * The operator's rule directory, which was documented and never read.
 *
 * `ZANSHIN_SEMGREP_RULES_DIR` appeared in the README and in the settings table of
 * document 04; the string existed nowhere in the code. Zanshin ships only the rules it
 * wrote, so this directory is the operator's only route to real coverage — and a scan ran
 * without it while saying otherwise.
 *
 * These tests exist so that the feature cannot go back to being a sentence in a document.
 */
describe('rules placed into a workspace', () => {
    let root: string;
    let workspace: Workspace;

    beforeEach(async () => {
        root = await mkdtemp(join(tmpdir(), 'zanshin-rules-test-'));
        workspace = { root, source: join(root, 'source'), rules: join(root, RULES_SUBDIR) };
        await placeBundledRules(workspace);
    });

    afterEach(async () => {
        await rm(root, { recursive: true, force: true });
    });

    async function operatorDirectory(files: Record<string, string>): Promise<string> {
        const directory = join(root, 'operator-rules');
        await mkdir(directory, { recursive: true });
        for (const [name, content] of Object.entries(files)) {
            await writeFile(join(directory, name), content, 'utf8');
        }
        return directory;
    }

    it('places the bundled tree where the scanners look for it', async () => {
        // gitleaks needs its configuration even when SAST is off, otherwise it falls back
        // to the scanned repository's own `.gitleaks.toml`.
        expect((await readdir(workspace.rules)).sort()).toEqual(['gitleaks', 'semgrep']);
    });

    it('does nothing when no directory is configured', async () => {
        expect(await placeOperatorRules(workspace, undefined)).toBe(false);
        expect(await placeOperatorRules(workspace, '')).toBe(false);
        expect(await placeOperatorRules(workspace, '   ')).toBe(false);

        expect(await readdir(join(workspace.rules, 'semgrep'))).not.toContain('operator');
    });

    it('merges the configured directory into the tree Semgrep walks', async () => {
        const directory = await operatorDirectory({ 'extra.yaml': 'rules: []\n' });

        expect(await placeOperatorRules(workspace, directory)).toBe(true);

        expect(await readdir(join(workspace.rules, 'semgrep', 'operator'))).toEqual(['extra.yaml']);
        // The bundled rules are still there: this is a merge, not a replacement.
        expect(await readdir(join(workspace.rules, 'semgrep'))).toContain('python');
    });

    it('keeps the operator rules apart so they cannot overwrite a bundled one', async () => {
        // Copying file by file into the same directory would let an operator file win on a
        // name collision, silently replacing a rule Zanshin ships.
        const directory = await operatorDirectory({ 'python': 'not a directory\n' });

        await placeOperatorRules(workspace, directory);

        const bundled = await readdir(join(workspace.rules, 'semgrep', 'python'));
        expect(bundled).toContain('dangerous-eval.yaml');
    });

    it('throws rather than scanning with the bundled rules alone', async () => {
        // The dangerous outcome is not the exception, it is the clean run: Semgrep would
        // exit 0 with a shorter list, which reads as "analyzed, those issues are gone" and
        // resolves everything the operator's rules had found.
        await expect(placeOperatorRules(workspace, join(root, 'does-not-exist'))).rejects.toBeInstanceOf(OperatorRulesUnavailable);
    });

    it('throws when the path is a file rather than a directory', async () => {
        const file = join(root, 'rules.yaml');
        await writeFile(file, 'rules: []\n', 'utf8');

        await expect(placeOperatorRules(workspace, file)).rejects.toThrow(/not a directory/);
    });

    it('names the variable in the failure, so the misconfiguration is findable', async () => {
        // This message reaches the operator through the scan's recorded failures. "ENOENT"
        // alone would send them looking at the repository rather than at their deployment.
        await expect(placeOperatorRules(workspace, join(root, 'missing'))).rejects.toThrow(/ZANSHIN_SEMGREP_RULES_DIR/);
    });
});
