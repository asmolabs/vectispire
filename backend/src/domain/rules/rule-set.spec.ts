import {
    InvalidRuleSetError,
    MAX_FILES,
    MAX_FILE_BYTES,
    acceptUpload,
    extractRuleIds,
    hashRuleSet,
    ruleIdsOf,
    triageImpact,
    type StoredRuleFile
} from './rule-set';

const rule = (id: string) => `rules:\n  - id: ${id}\n    languages: [python]\n    message: x\n    severity: ERROR\n    pattern: eval(...)\n`;

describe('accepting an upload', () => {
    it('renames every file to a path Zanshin chose', () => {
        // Path traversal is removed as a class rather than filtered for: there is no
        // attacker-controlled path left to escape from.
        const stored = acceptUpload([
            { name: '../../etc/passwd.yaml', content: rule('a') },
            { name: 'ok.yml', content: rule('b') }
        ]);

        expect(stored.map((file) => file.path)).toEqual(['rule-0001.yaml', 'rule-0002.yaml']);
        expect(stored[0].originalName).toBe('../../etc/passwd.yaml');
    });

    it('keeps the content byte for byte', () => {
        // Zanshin does not parse, reformat or normalize these bytes — Semgrep does, inside a
        // locked-down container. Anything else here would be a YAML parser in the request
        // path, which is what this module exists to avoid.
        const content = rule('untouched') + '\n# a trailing comment\n';
        expect(acceptUpload([{ name: 'r.yaml', content }])[0].content).toBe(content);
    });

    it('refuses anything that is not a YAML file', () => {
        expect(() => acceptUpload([{ name: 'rules.tar.gz', content: 'x' }])).toThrow(/not a YAML file/);
        expect(() => acceptUpload([{ name: 'rules', content: 'x' }])).toThrow(InvalidRuleSetError);
    });

    it('refuses rather than filtering silently', () => {
        // An operator who uploaded forty files and got thirty-eight stored would have
        // coverage they believe they have and do not.
        expect(() => acceptUpload([{ name: 'good.yaml', content: rule('a') }, { name: 'bad.txt', content: 'x' }])).toThrow(
            InvalidRuleSetError
        );
    });

    it('refuses an empty upload and an empty file', () => {
        expect(() => acceptUpload([])).toThrow(/No file/);
        expect(() => acceptUpload([{ name: 'empty.yaml', content: '' }])).toThrow(/is empty/);
    });

    it('caps one file and the whole upload', () => {
        const big = 'x'.repeat(MAX_FILE_BYTES + 1);
        expect(() => acceptUpload([{ name: 'big.yaml', content: big }])).toThrow(/over the/);

        const many = Array.from({ length: MAX_FILES + 1 }, (_, i) => ({ name: `r${i}.yaml`, content: rule(`r${i}`) }));
        expect(() => acceptUpload(many)).toThrow(/Too many files/);
    });

    it('counts the size in bytes, not characters', () => {
        // A file of accented characters is twice its length in UTF-8; measuring in
        // characters would let through twice the intended payload.
        const accented = 'é'.repeat(MAX_FILE_BYTES / 2 + 1);
        expect(() => acceptUpload([{ name: 'a.yaml', content: accented }])).toThrow(/over the/);
    });
});

describe('extracting rule ids', () => {
    it('reads the ids a rule file declares', () => {
        expect(extractRuleIds(rule('python.lang.security.eval'))).toEqual(['python.lang.security.eval']);
    });

    it('reads several rules from one file', () => {
        expect(ruleIdsOf(acceptUpload([{ name: 'r.yaml', content: rule('a') + rule('b') }]))).toEqual(new Set(['a', 'b']));
    });

    it('tolerates quoting and list indentation', () => {
        expect(extractRuleIds(`rules:\n  - id: "quoted-id"\n  - id: 'single'\n`)).toEqual(['quoted-id', 'single']);
    });

    it('does not mistake another key ending in id for a rule id', () => {
        expect(extractRuleIds('metadata:\n  cwe_id: CWE-95\n  ruleid: nope\n')).toEqual([]);
    });

    it('misses nothing that matters when it misses something', () => {
        // **Advisory only, by design.** A rule whose id this does not match is still shipped
        // to Semgrep and still runs; it is absent from the counts and from the impact
        // warning, and nothing about a scan's correctness depends on that. An exhaustive
        // answer would need a YAML parser in the request path.
        const exotic = 'rules:\n  - {id: inline-flow-style}\n';
        expect(extractRuleIds(exotic)).toEqual([]);
        expect(acceptUpload([{ name: 'r.yaml', content: exotic }])[0].content).toBe(exotic);
    });
});

describe('the hash an executor caches on', () => {
    const files = acceptUpload([{ name: 'a.yaml', content: rule('a') }]);

    it('is stable for the same content', () => {
        expect(hashRuleSet(files)).toBe(hashRuleSet(acceptUpload([{ name: 'a.yaml', content: rule('a') }])));
    });

    it('ignores the names the operator uploaded', () => {
        // Re-uploading the same rules under different filenames must not invalidate every
        // agent's cache.
        expect(hashRuleSet(acceptUpload([{ name: 'renamed.yml', content: rule('a') }]))).toBe(hashRuleSet(files));
    });

    it('changes when a rule changes', () => {
        expect(hashRuleSet(acceptUpload([{ name: 'a.yaml', content: rule('b') }]))).not.toBe(hashRuleSet(files));
    });

    it('separates the fields, so content cannot imitate a boundary', () => {
        const a: StoredRuleFile[] = [
            { path: 'rule-0001.yaml', originalName: 'x', content: 'ab' },
            { path: 'rule-0002.yaml', originalName: 'y', content: 'cd' }
        ];
        const b: StoredRuleFile[] = [
            { path: 'rule-0001.yaml', originalName: 'x', content: 'a' },
            { path: 'rule-0002.yaml', originalName: 'y', content: 'bcd' }
        ];
        expect(hashRuleSet(a)).not.toBe(hashRuleSet(b));
    });
});

describe('triage impact of an activation', () => {
    it('names the rules whose open issues would be resolved', () => {
        // A rule id enters an issue's fingerprint, so a rule that disappears takes its
        // issues with it — with their triage decisions, justifications and review dates.
        const impact = triageImpact(
            new Set(['keep', 'drop']),
            new Set(['keep', 'new']),
            new Map([
                ['keep', 3],
                ['drop', 12]
            ])
        );

        expect(impact.losingIssues).toEqual(['drop']);
        expect(impact.affectedIssues).toBe(12);
        expect(impact.addedRules).toBe(1);
        expect(impact.removedRules).toBe(1);
    });

    it('counts only issues that are open, since a resolved one has nothing to lose', () => {
        // The caller passes open issues only; this asserts the arithmetic follows that map
        // rather than the rule sets.
        const impact = triageImpact(new Set(['gone']), new Set([]), new Map());
        expect(impact.losingIssues).toEqual([]);
        expect(impact.affectedIssues).toBe(0);
        expect(impact.removedRules).toBe(1);
    });

    it('reports nothing lost when the new set is a superset', () => {
        const impact = triageImpact(new Set(['a']), new Set(['a', 'b']), new Map([['a', 5]]));
        expect(impact.losingIssues).toEqual([]);
        expect(impact.affectedIssues).toBe(0);
        expect(impact.addedRules).toBe(1);
    });

    it('flags an issue whose rule was never in the declared set either', () => {
        // The backlog is the authority on what has issues, not the previous upload: rules
        // can also arrive from the bundled tree or from ZANSHIN_SEMGREP_RULES_DIR.
        const impact = triageImpact(new Set([]), new Set(['b']), new Map([['from-elsewhere', 4]]));
        expect(impact.losingIssues).toEqual(['from-elsewhere']);
        expect(impact.affectedIssues).toBe(4);
    });

    it('sorts the list, so the warning reads the same twice', () => {
        const impact = triageImpact(
            new Set([]),
            new Set([]),
            new Map([
                ['z', 1],
                ['a', 1]
            ])
        );
        expect(impact.losingIssues).toEqual(['a', 'z']);
    });
});
