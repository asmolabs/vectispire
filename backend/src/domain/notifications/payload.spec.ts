import { MAX_DETAILED_ISSUES, type NotifiableIssue, buildPayload, selectNotable } from './payload';

function issue(values: Partial<NotifiableIssue>): NotifiableIssue {
    return {
        id: 1,
        identifier: 'CVE-2021-44228',
        type: 'vulnerability',
        severity: 'high',
        isKev: false,
        epssScore: null,
        packageName: null,
        filePath: null,
        fixVersions: null,
        link: null,
        ...values
    };
}

describe('selectNotable', () => {
    const options = { minSeverity: 'high', alwaysOnKev: true };

    it('retient ce qui atteint le seuil', () => {
        const selected = selectNotable([issue({ severity: 'critical' }), issue({ severity: 'low' })], options);

        expect(selected).toHaveLength(1);
        expect(selected[0].severity).toBe('critical');
    });

    it('retient une vulnérabilité exploitée sous le seuil', () => {
        // Tout l'intérêt du signal KEV : la sévérité seule écarterait un « moyen »
        // exploité aujourd'hui.
        const selected = selectNotable([issue({ severity: 'medium', isKev: true })], options);

        expect(selected).toHaveLength(1);
    });

    it('respecte le réglage quand KEV ne prime pas', () => {
        expect(selectNotable([issue({ severity: 'medium', isKev: true })], { minSeverity: 'high', alwaysOnKev: false })).toEqual([]);
    });

    it("n'envoie jamais de constat de qualité, même au-dessus du seuil", () => {
        // Semgrep traduit `ERROR` en `high` : sans cette exclusion, le premier scan d'un
        // dépôt avec le SAST activé déclencherait un webhook annonçant des centaines de
        // problèmes, et le canal serait filtré dès le lendemain.
        const selected = selectNotable([issue({ type: 'quality', severity: 'critical' }), issue({ type: 'quality', isKev: true })], options);

        expect(selected).toEqual([]);
    });
});

describe('buildPayload', () => {
    const base = { targetName: 'org/projet', scanId: 42, resolvedCount: 0, minSeverity: 'high' };

    it("met en tête une phrase lisible pour les récepteurs qui n'en lisent qu'une", () => {
        const payload = buildPayload({
            ...base,
            newIssues: [issue({}), issue({ id: 2, isKev: true })],
            reopenedIssues: [issue({ id: 3 })],
            resolvedCount: 4
        });

        expect(payload.text).toBe('Zanshin — org/projet : 2 nouveau(x) problème(s), 1 réapparu(s), 1 activement exploité(s) (4 résolu(s))');
        expect(payload.kev_count).toBe(1);
        expect(payload.new_count).toBe(2);
        expect(payload.reopened_count).toBe(1);
        expect(payload.resolved_count).toBe(4);
    });

    it('borne le détail et annonce combien manquent', () => {
        // Un corps à quatre cents entrées est un déni de service contre son lecteur.
        const many = Array.from({ length: 25 }, (_, index) => issue({ id: index }));
        const payload = buildPayload({ ...base, newIssues: many, reopenedIssues: [] });

        expect(payload.issues).toHaveLength(MAX_DETAILED_ISSUES);
        expect(payload.truncated).toBe(15);
    });

    it("n'expose que les champs prévus d'un problème", () => {
        // La charge part vers un système tiers : la projection est explicite pour qu'une
        // colonne ajoutée un jour à `Issue` n'y arrive pas par inadvertance.
        const payload = buildPayload({ ...base, newIssues: [issue({ fixVersions: '2.17.1' })], reopenedIssues: [] });

        expect(Object.keys((payload.issues as unknown[])[0] as object).sort()).toEqual([
            'epss_score',
            'file_path',
            'fix_versions',
            'id',
            'identifier',
            'is_kev',
            'link',
            'package',
            'severity',
            'type'
        ]);
    });
});
