import { SETTINGS_CATALOG, definitionFor, validate } from './catalog';

describe('catalogue des réglages', () => {
    it("n'expose que des clés dont un service porté est le lecteur", () => {
        // La règle du fichier : un formulaire qui accepte une valeur et n'en fait rien est
        // pire qu'un formulaire qui ne l'offre pas. Ces clés-là n'ont pas encore de
        // lecteur — les exposer ferait croire à une configuration sans effet.
        // Tous les autres réglages ont désormais leur lecteur. Reste le jeton, qui n'est
        // pas absent faute de lecteur mais **parce que c'est un secret** : il est chiffré
        // au repos, et un formulaire qui le réafficherait le remettrait en clair à l'écran.
        expect(definitionFor('ticket_token')).toBeUndefined();
    });

    it('donne à chaque réglage un type, une section et une explication', () => {
        for (const definition of SETTINGS_CATALOG) {
            expect(definition.section).not.toBe('');
            expect(definition.label).not.toBe('');
            // L'explication porte ce que le réglage **ne** fait pas, qui est la partie
            // qu'un opérateur ne peut pas deviner.
            expect(definition.help.length).toBeGreaterThan(40);
        }
    });

    it("n'a pas deux fois la même clé", () => {
        const keys = SETTINGS_CATALOG.map((definition) => definition.key);

        expect(new Set(keys).size).toBe(keys.length);
    });

    it('accepte son propre défaut pour chaque réglage', () => {
        // Le piège discret : un défaut que la validation refuserait rendrait l'écran
        // impossible à enregistrer sans rien y changer.
        for (const definition of SETTINGS_CATALOG) {
            expect(validate(definition, definition.default)).toBeNull();
        }
    });
});

describe('validate', () => {
    const boolean = definitionFor('enrichment_enabled')!;
    const integer = definitionFor('retention_max_age_days')!;
    const severity = definitionFor('notification_min_severity')!;

    it('refuse un booléen approximatif', () => {
        expect(validate(boolean, 'true')).toBeNull();
        expect(validate(boolean, 'oui')).toMatch(/true/);
        expect(validate(boolean, '1')).not.toBeNull();
    });

    it('refuse un entier illisible plutôt que de le lire comme zéro', () => {
        // Zéro veut dire « aucune limite » : une faute de frappe qui se lirait zéro
        // désactiverait la rétention en silence.
        expect(validate(integer, '90')).toBeNull();
        expect(validate(integer, '0')).toBeNull();
        expect(validate(integer, '')).not.toBeNull();
        expect(validate(integer, 'quatre-vingt-dix')).not.toBeNull();
        expect(validate(integer, '-1')).not.toBeNull();
        expect(validate(integer, '1.5')).not.toBeNull();
    });

    it('refuse une sévérité hors vocabulaire', () => {
        // Une valeur hors vocabulaire se propagerait en silence jusqu'au tri, au résumé et
        // au gate.
        expect(validate(severity, 'high')).toBeNull();
        expect(validate(severity, 'HIGH')).not.toBeNull();
        expect(validate(severity, 'grave')).not.toBeNull();
    });
});

describe('réglages sensibles', () => {
    it("marque comme sensible tout réglage dont la valeur est une capacité", () => {
        // Une URL de webhook Slack ou Teams n'est pas une configuration : qui la connaît
        // peut publier dans le canal où l'équipe attend les alertes de Zanshin. C'est
        // précisément le canal où un message forgé porte le plus.
        expect(definitionFor('notification_webhook_url')?.sensitive).toBe(true);
    });

    it("marque comme sensible ce qui cartographie le réseau interne", () => {
        // Pas un secret au sens strict, mais un compte sans droits n'a aucune raison de
        // découvrir l'adresse du GitLab interne ou de l'hôte qui fait tourner le modèle.
        expect(definitionFor('ticket_base_url')?.sensitive).toBe(true);
        expect(definitionFor('ai_review_ollama_url')?.sensitive).toBe(true);
    });

    it('laisse non sensible ce qui ne dit rien de plus que le comportement', () => {
        // Tout marquer sensible reviendrait à ne rien marquer : l'écran perdrait ses
        // valeurs pour un non-administrateur sans qu'aucun secret soit en jeu.
        expect(definitionFor('enrichment_enabled')?.sensitive).toBeFalsy();
        expect(definitionFor('retention_max_age_days')?.sensitive).toBeFalsy();
        expect(definitionFor('notification_min_severity')?.sensitive).toBeFalsy();
    });
});
