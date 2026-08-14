import { agentAccepts, normalizeRequiredLabel, parseAgentLabels } from './targeting';

describe("ciblage d'un scan vers un agent", () => {
    describe('étiquettes annoncées par un agent', () => {
        it('sépare, élague et abaisse la casse', () => {
            // « Production » et « production », saisis à six mois d'intervalle sur deux
            // écrans, doivent désigner la même chose : sinon un scan attend indéfiniment un
            // agent qui est là, et rien à l'écran n'explique pourquoi.
            expect(parseAgentLabels(' Production , réseau-client ')).toEqual(['production', 'réseau-client']);
        });

        it('ne rend aucune étiquette pour un agent qui n’en déclare pas', () => {
            expect(parseAgentLabels(null)).toEqual([]);
            expect(parseAgentLabels('')).toEqual([]);
            // Des virgules seules ne sont pas des étiquettes : sans ce filtre, la chaîne
            // vide entrerait dans la liste et satisferait une exigence vide.
            expect(parseAgentLabels(' , , ')).toEqual([]);
        });

        it('ne compte pas deux fois la même étiquette', () => {
            expect(parseAgentLabels('prod,PROD, prod ')).toEqual(['prod']);
        });
    });

    describe("exigence portée par une cible", () => {
        it('normalise comme les étiquettes, pour que la comparaison ait un sens', () => {
            expect(normalizeRequiredLabel('  Réseau-Client ')).toBe('réseau-client');
        });

        it('traite un champ vidé comme « plus d’exigence »', () => {
            // **Le cas qui bloquerait une file en silence.** Stocker la chaîne vide donnerait
            // une exigence qu'aucun agent ne satisfait jamais, et le scan attendrait sans
            // que rien ne le dise.
            expect(normalizeRequiredLabel('')).toBeNull();
            expect(normalizeRequiredLabel('   ')).toBeNull();
            expect(normalizeRequiredLabel(null)).toBeNull();
        });
    });

    describe('décision', () => {
        it('laisse un scan sans exigence à qui le demande', () => {
            // Le comportement d'avant. Exiger rétroactivement une étiquette arrêterait
            // toutes les files existantes au premier déploiement.
            expect(agentAccepts([], null)).toBe(true);
            expect(agentAccepts(['prod'], null)).toBe(true);
        });

        it('réserve un scan exigeant à l’agent qui porte l’étiquette', () => {
            expect(agentAccepts(['prod', 'client'], 'client')).toBe(true);
            expect(agentAccepts(['prod'], 'client')).toBe(false);
        });

        it('ne laisse pas un agent sans étiquette correspondre à tout', () => {
            // **Fermé par défaut du côté de l'agent.** L'inverse — « aucune étiquette veut
            // dire toutes » — est la lecture séduisante, et elle rendrait l'exigence
            // inopérante au premier agent qu'on enregistre sans y penser.
            expect(agentAccepts([], 'client')).toBe(false);
        });
    });
});
