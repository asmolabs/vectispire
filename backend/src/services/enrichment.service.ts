import { Injectable, Logger } from '@nestjs/common';
import {
    EPSS_API_URL,
    KEV_CATALOG_URL,
    batches,
    parseEpssResponse,
    parseKevCatalog
} from '../domain/enrichment/catalogs';
import { TYPE_VULNERABILITY } from '../domain/issues/types';
import { Finding } from '../persistence/entities';
import { SettingsService } from './settings.service';

/** La clé de réglage. Activé par défaut : les deux sources sont publiques et gratuites. */
export const SETTING_ENRICHMENT_ENABLED = 'enrichment_enabled';

/** Le catalogue KEV change au plus une fois par jour ; le relire à chaque scan serait du gâchis. */
const KEV_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

const HTTP_TIMEOUT_MS = 10_000;

/**
 * L'enrichissement des vulnérabilités par EPSS et le catalogue KEV de la CISA.
 *
 * **Ce sont les seuls appels réseau que fait Zanshin pendant un scan, et ils n'envoient
 * que des identifiants de CVE** — jamais de code source, jamais de SBOM. C'est ce qui les
 * distingue d'un scanner infonuagique et ce qui rend le compromis acceptable.
 *
 * **Toute panne est journalisée et avalée.** Un scan qui a produit de vrais résultats ne
 * doit jamais être marqué en échec parce qu'une API facultative n'a pas répondu. La
 * contrepartie est réelle et se voit à l'écran : `is_kev` restera faux, donc le compteur
 * « activement exploitées » affichera un zéro rassurant qui veut dire « on n'a pas pu
 * demander », pas « il n'y en a pas ».
 */
@Injectable()
export class EnrichmentService {
    private readonly logger = new Logger(EnrichmentService.name);

    /**
     * Le cache du catalogue KEV, porté par l'instance.
     *
     * L'instance est un singleton Nest — contrairement au service Python, recréé à chaque
     * requête, qui devait pour cette raison mettre son cache sur la classe. Ici la portée
     * d'instance suffit et évite qu'un test contamine le suivant.
     */
    private kevCache: Set<string> = new Set();
    private kevFetchedAt = 0;

    constructor(
        private readonly settings: SettingsService,
        /** Injectable pour les tests : sans cela, les vérifier demanderait un réseau. */
        private readonly fetchJson: (url: string) => Promise<unknown> = defaultFetchJson
    ) {}

    async isEnabled(): Promise<boolean> {
        return this.settings.isEnabled(SETTING_ENRICHMENT_ENABLED, true);
    }

    /**
     * Pose `epssScore` et `isKev` sur les constats de vulnérabilité, **en mémoire**.
     *
     * Rien n'est écrit ici : l'appelant est au milieu de la transaction d'ingestion et
     * enregistrera ces constats lui-même. Écrire depuis ce service imposerait sa propre
     * transaction et ferait apparaître les constats en base avant que le scan ne soit
     * conclu — visibles à mi-chemin, avec des compteurs qui ne correspondent à rien.
     */
    async enrich(findings: Finding[]): Promise<void> {
        if (!(await this.isEnabled())) return;

        // Le filtre porte le type : `identifier` est nullable sur l'entité, et un constat
        // sans identifiant n'a rien à demander aux catalogues.
        const vulnerabilities = findings.filter(
            (finding): finding is Finding & { identifier: string } => finding.type === TYPE_VULNERABILITY && Boolean(finding.identifier)
        );
        if (vulnerabilities.length === 0) return;

        const identifiers = [...new Set(vulnerabilities.map((finding) => finding.identifier))].sort();
        const [scores, kev] = await Promise.all([this.epssScores(identifiers), this.kevIdentifiers()]);

        for (const finding of vulnerabilities) {
            const score = scores.get(finding.identifier);
            // Seulement si connu : écraser par `null` effacerait un score obtenu au scan
            // précédent, le jour où l'API est indisponible.
            if (score !== undefined) finding.epssScore = score;
            finding.isKev = kev.has(finding.identifier);
        }

        this.logger.log(
            `Enrichissement : ${scores.size}/${identifiers.length} CVE avec un score EPSS, ` +
                `${vulnerabilities.filter((finding) => finding.isKev).length} au catalogue KEV.`
        );
    }

    private async epssScores(identifiers: string[]): Promise<Map<string, number>> {
        const scores = new Map<string, number>();

        for (const batch of batches(identifiers)) {
            try {
                const payload = await this.fetchJson(`${EPSS_API_URL}?cve=${encodeURIComponent(batch.join(','))}`);
                for (const [cve, score] of parseEpssResponse(payload)) scores.set(cve, score);
            } catch (error) {
                // Un lot perdu n'annule pas les autres : un enrichissement partiel vaut
                // mieux qu'aucun, et les CVE manquants seront retentés au scan suivant.
                this.logger.warn(`Interrogation EPSS échouée pour un lot de ${batch.length} CVE : ${(error as Error).message}`);
            }
        }
        return scores;
    }

    private async kevIdentifiers(): Promise<Set<string>> {
        if (this.kevCache.size > 0 && Date.now() - this.kevFetchedAt < KEV_CACHE_TTL_MS) return this.kevCache;

        try {
            const catalog = parseKevCatalog(await this.fetchJson(KEV_CATALOG_URL));
            // Un catalogue vide n'est jamais légitime — il en contient plus d'un millier.
            // Le retenir marquerait toutes les vulnérabilités comme non exploitées pendant
            // vingt-quatre heures, ce qui est exactement le mensonge à éviter.
            if (catalog.size > 0) {
                this.kevCache = catalog;
                this.kevFetchedAt = Date.now();
            } else {
                this.logger.warn('Catalogue KEV vide ou illisible : ancien cache conservé.');
            }
        } catch (error) {
            this.logger.warn(`Récupération du catalogue KEV échouée : ${(error as Error).message} — ancien cache conservé.`);
        }

        return this.kevCache;
    }
}

/** Un GET JSON borné dans le temps. Sans délai, un serveur muet retiendrait le scan. */
async function defaultFetchJson(url: string): Promise<unknown> {
    const response = await fetch(url, { signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
}

/** Le type de la dépendance injectable, pour les tests et le module. */
export type FetchJson = (url: string) => Promise<unknown>;
