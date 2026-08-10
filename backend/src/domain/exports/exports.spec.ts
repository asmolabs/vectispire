import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CSV_COLUMNS, ExportableIssue, buildIssuesCsv, buildOpenVexDocument, buildSarifDocument } from './exports';

interface ExportVector {
    label: string;
    issues: ExportableIssue[];
    sarif: Record<string, unknown>;
    openvex: Record<string, unknown>;
    csv: string;
}

const vectors: { cases: ExportVector[]; sarifWithoutInformationUri: Record<string, unknown> } = JSON.parse(readFileSync(join(__dirname, '../../../test/vectors/exports.json'), 'utf8'));

const SARIF_OPTIONS = { targetName: 'org/exemple', toolVersion: '1.2.3', informationUri: 'https://zanshin.interne' };
const VEX_OPTIONS = {
    author: 'Zanshin <security@exemple.be>',
    productId: 'pkg:github/org/exemple',
    documentId: 'https://zanshin.interne/vex/1',
    timestamp: '2026-08-10T08:00:00',
    version: 3
};

describe('exports', () => {
    it('dispose de vecteurs générés depuis le code Python', () => {
        expect(vectors.cases.length).toBeGreaterThan(0);
    });

    describe.each(vectors.cases)('$label', (vector) => {
        it('rend le même document SARIF', () => {
            expect(buildSarifDocument(vector.issues, SARIF_OPTIONS)).toEqual(vector.sarif);
        });

        it('rend le même document OpenVEX', () => {
            expect(buildOpenVexDocument(vector.issues, VEX_OPTIONS)).toEqual(vector.openvex);
        });

        it('rend le même CSV, octet pour octet', () => {
            expect(buildIssuesCsv(vector.issues)).toBe(vector.csv);
        });
    });

    it("omet informationUri plutôt que de l'écrire nulle", () => {
        // `**({...} if x else {})` en Python : la clé est absente, pas nulle. Un
        // consommateur strict du schéma refuse `"informationUri": null`.
        const document = buildSarifDocument([vectors.cases[1].issues[0]], { targetName: 'org/exemple', toolVersion: '1.2.3' });
        expect(document).toEqual(vectors.sarifWithoutInformationUri);
        const driver = (document.runs as { tool: { driver: Record<string, unknown> } }[])[0].tool.driver;
        expect('informationUri' in driver).toBe(false);
    });
});

describe('les détails de format qu’un portage rate', () => {
    const issue = vectors.cases[1].issues[0];

    it('termine les lignes CSV en CRLF, y compris la dernière', () => {
        const csv = buildIssuesCsv([issue]);
        expect(csv.endsWith('\r\n')).toBe(true);
        expect(csv.split('\r\n').filter(Boolean)).toHaveLength(2);
        // Aucun \n isolé : ce serait un fichier que la plupart des outils liraient
        // quand même, donc un écart que personne ne remarquerait avant qu'un
        // consommateur strict ne le refuse.
        expect(csv.replace(/\r\n/g, '')).not.toContain('\n');
    });

    it("écrit les scores entiers avec leur décimale, comme str(float) en Python", () => {
        const row = buildIssuesCsv([{ ...issue, cvssScore: 9, epssScore: 1 }]).split('\r\n')[1].split(',');
        expect(row[4]).toBe('9.0');
        expect(row[5]).toBe('1.0');
    });

    it('distingue un score nul d’un score absent', () => {
        const withZero = buildIssuesCsv([{ ...issue, cvssScore: 0, epssScore: 0 }]).split('\r\n')[1].split(',');
        expect(withZero[4]).toBe('0.0');
        const withNull = buildIssuesCsv([{ ...issue, cvssScore: null, epssScore: null }]).split('\r\n')[1].split(',');
        expect(withNull[4]).toBe('');
    });

    it('cite un champ contenant une virgule, un guillemet ou un saut de ligne', () => {
        const csv = buildIssuesCsv([{ ...issue, triageComment: null, link: 'a,b' }]);
        expect(csv).toContain('"a,b"');
        expect(buildIssuesCsv([{ ...issue, link: 'a"b' }])).toContain('"a""b"');
        expect(buildIssuesCsv([{ ...issue, link: 'a\nb' }])).toContain('"a\nb"');
    });

    it('ne cite pas ce qui n’en a pas besoin', () => {
        expect(buildIssuesCsv([{ ...issue, link: 'simple' }])).toContain(',simple');
    });

    it('a exactement les 25 colonnes de Python, dans l’ordre', () => {
        expect(CSV_COLUMNS).toHaveLength(25);
        expect(buildIssuesCsv([]).trim()).toBe(CSV_COLUMNS.join(','));
    });
});

describe('les invariants SARIF, qui décident de ce que GitHub affiche', () => {
    const issue = vectors.cases[1].issues[0];
    const runs = (document: Record<string, unknown>) => (document.runs as { results: Record<string, unknown>[]; tool: { driver: { rules: Record<string, unknown>[] } } }[])[0];

    it('donne une location à chaque résultat, même sans fichier', () => {
        // GitHub jette silencieusement les résultats sans location. Une location
        // « honnêtement vide » ferait disparaître l'essentiel des vulnérabilités.
        const document = buildSarifDocument([{ ...issue, filePath: null, line: null }], SARIF_OPTIONS);
        const locations = runs(document).results[0].locations as { physicalLocation: { artifactLocation: { uri: string } } }[];
        expect(locations).toHaveLength(1);
        expect(locations[0].physicalLocation.artifactLocation.uri).toBe('.');
    });

    it('supprime les problèmes triés au lieu de les omettre', () => {
        // Les retirer ferait qu'une plateforme les re-signale comme neufs au
        // téléversement suivant, défaisant le travail de triage.
        const triaged = { ...issue, triageStatus: 'not_affected', triageJustification: 'component_not_present' };
        const results = runs(buildSarifDocument([triaged], SARIF_OPTIONS)).results;
        expect(results).toHaveLength(1);
        expect(results[0].suppressions).toBeDefined();
    });

    it('ne supprime pas un « affected » : décider qu’un problème est réel doit rester visible', () => {
        const results = runs(buildSarifDocument([{ ...issue, triageStatus: 'affected' }], SARIF_OPTIONS)).results;
        expect(results[0].suppressions).toBeUndefined();
    });

    it('étiquette la qualité « quality » et non « security »', () => {
        // Sans cela, chaque constat de qualité remonterait dans GitHub code scanning
        // comme une alerte de sécurité.
        const rules = runs(buildSarifDocument([{ ...issue, type: 'quality' }], SARIF_OPTIONS)).tool.driver.rules;
        expect((rules[0].properties as { tags: string[] }).tags).toEqual(['quality', 'quality']);
    });

    it('porte security-severity, sur laquelle GitHub classe réellement', () => {
        const rules = runs(buildSarifDocument([{ ...issue, severity: 'critical' }], SARIF_OPTIONS)).tool.driver.rules;
        expect((rules[0].properties as Record<string, unknown>)['security-severity']).toBe('9.5');
    });

    it('n’invente pas de security-severity pour une sévérité hors vocabulaire', () => {
        const rules = runs(buildSarifDocument([{ ...issue, severity: 'catastrophique' }], SARIF_OPTIONS)).tool.driver.rules;
        expect((rules[0].properties as Record<string, unknown>)['security-severity']).toBeUndefined();
    });

    it('numérote les règles dans leur ordre d’apparition', () => {
        // `ruleIndex` pointe dans le tableau `rules` : une désynchronisation ferait
        // afficher la mauvaise règle sous chaque résultat.
        const document = buildSarifDocument(
            [
                { ...issue, id: 1, identifier: 'CVE-A' },
                { ...issue, id: 2, identifier: 'CVE-B' },
                { ...issue, id: 3, identifier: 'CVE-A' }
            ],
            SARIF_OPTIONS
        );
        const { results, tool } = runs(document);
        expect(tool.driver.rules).toHaveLength(2);
        expect(results.map((result) => result.ruleIndex)).toEqual([0, 1, 0]);
        for (const result of results) {
            expect(tool.driver.rules[result.ruleIndex as number].id).toBe(result.ruleId);
        }
    });
});

describe('les invariants OpenVEX', () => {
    const issue = vectors.cases[1].issues[0];
    const statements = (document: Record<string, unknown>) => document.statements as Record<string, unknown>[];

    it('n’émet une déclaration que pour une vulnérabilité identifiée', () => {
        expect(statements(buildOpenVexDocument([{ ...issue, type: 'secret' }], VEX_OPTIONS))).toHaveLength(0);
        expect(statements(buildOpenVexDocument([{ ...issue, identifier: null }], VEX_OPTIONS))).toHaveLength(0);
    });

    it('déclare « fixed » un problème résolu jamais trié', () => {
        // Dire « sous investigation » de quelque chose que le scanner ne voit plus
        // serait trompeur dans un document fait pour répondre exactement à ça.
        const [statement] = statements(buildOpenVexDocument([{ ...issue, state: 'resolved', triageStatus: 'under_review' }], VEX_OPTIONS));
        expect(statement.status).toBe('fixed');
    });

    it('traduit under_review en under_investigation, le seul écart de vocabulaire', () => {
        const [statement] = statements(buildOpenVexDocument([issue], VEX_OPTIONS));
        expect(statement.status).toBe('under_investigation');
    });

    it('porte la justification requise par la spécification pour not_affected', () => {
        const [statement] = statements(buildOpenVexDocument([{ ...issue, triageStatus: 'not_affected', triageJustification: 'component_not_present' }], VEX_OPTIONS));
        expect(statement.justification).toBe('component_not_present');
    });

    it('range le texte libre dans impact_statement ou action_statement selon le statut', () => {
        const notAffected = statements(buildOpenVexDocument([{ ...issue, triageStatus: 'not_affected', triageJustification: 'j', triageComment: 'texte' }], VEX_OPTIONS))[0];
        expect(notAffected.impact_statement).toBe('texte');
        expect(notAffected.action_statement).toBeUndefined();

        const affected = statements(buildOpenVexDocument([{ ...issue, triageStatus: 'affected', triageComment: 'texte' }], VEX_OPTIONS))[0];
        expect(affected.action_statement).toBe('texte');
        expect(affected.impact_statement).toBeUndefined();
    });
});
