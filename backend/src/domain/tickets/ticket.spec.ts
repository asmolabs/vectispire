import { type TicketableIssue, buildBody, buildTitle, parseLabels, parseProvider } from './ticket';

function issue(values: Partial<TicketableIssue> = {}): TicketableIssue {
    return {
        id: 12,
        type: 'vulnerability',
        identifier: 'CVE-2021-44228',
        severity: 'critical',
        packageName: 'log4j-core',
        packageVersion: '2.14.1',
        fixVersions: null,
        fixState: null,
        isDirectDependency: null,
        filePath: null,
        line: null,
        isKev: false,
        epssScore: null,
        link: null,
        description: null,
        fingerprint: 'abc123',
        ...values
    };
}

describe('buildTitle', () => {
    it('reste court et recherchable', () => {
        expect(buildTitle(issue(), 'org/projet')).toBe('[Zanshin][CRITICAL] CVE-2021-44228 — log4j-core (org/projet)');
    });

    it('retombe sur le type quand il n\'y a pas d\'identifiant', () => {
        expect(buildTitle(issue({ identifier: null, type: 'secret', packageName: null, severity: null }), 'org/projet')).toBe(
            '[Zanshin][UNKNOWN] secret (org/projet)'
        );
    });
});

describe('buildBody', () => {
    it('met la version corrigée en tête des détails', () => {
        // C'est elle qui fait la différence entre un ticket fermé aujourd'hui et un ticket
        // traîné sur trois itérations.
        const body = buildBody(issue({ fixVersions: '2.17.1' }), 'org/projet');

        expect(body).toContain('**Corrigé dans : 2.17.1**');
        expect(body.indexOf('Corrigé dans')).toBeLessThan(body.indexOf('Composant'));
    });

    it("dit explicitement qu'aucun correctif n'existe", () => {
        // Le silence se lirait « on n'a pas regardé », alors que c'est une information :
        // il n'y a rien à mettre à jour, il faut atténuer autrement.
        expect(buildBody(issue({ fixState: 'not-fixed' }), 'org/projet')).toContain('Aucun correctif publié');
    });

    it("signale l'exploitation active et le score EPSS", () => {
        const body = buildBody(issue({ isKev: true, epssScore: 0.97512 }), 'org/projet');

        expect(body).toContain('Exploitation active connue');
        expect(body).toContain('97.5 %');
    });

    it('distingue une dépendance directe d\'une transitive', () => {
        expect(buildBody(issue({ isDirectDependency: true }), 'org/projet')).toContain('directe (déclarée par le projet)');
        expect(buildBody(issue({ isDirectDependency: false }), 'org/projet')).toContain('transitive');
        // `null` veut dire « on ne sait pas » : ne rien dire vaut mieux que deviner.
        expect(buildBody(issue(), 'org/projet')).not.toContain('Dépendance :');
    });

    it('tronque une description bavarde', () => {
        // Un ticket qu'on doit dérouler pour trouver la conclusion n'est pas lu.
        const body = buildBody(issue({ description: 'x'.repeat(5000) }), 'org/projet');

        expect(body).toContain('x'.repeat(1000));
        expect(body).not.toContain('x'.repeat(1001));
    });

    it("porte l'empreinte et la raison de son ouverture", () => {
        // L'empreinte permet de retrouver le problème depuis le ticket ; la raison évite
        // la question « pourquoi celui-là et pas l'autre ».
        const body = buildBody(issue(), 'org/projet');

        expect(body).toContain('empreinte `abc123`');
        expect(body).toContain('ferait échouer une compilation');
    });
});

describe('parseLabels', () => {
    it('découpe et nettoie', () => {
        expect(parseLabels('zanshin, security ,')).toEqual(['zanshin', 'security']);
        expect(parseLabels('')).toEqual([]);
    });
});

describe('parseProvider', () => {
    it('normalise et refuse ce qui sort du vocabulaire', () => {
        expect(parseProvider('  GitLab ')).toBe('gitlab');
        expect(parseProvider('github')).toBe('none');
        expect(parseProvider('')).toBe('none');
    });
});
