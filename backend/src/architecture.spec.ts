import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

/**
 * La règle de couches, exprimée en graphe d'imports.
 *
 * ```
 *   api/ ──► services/ ──► repositories/ ──► persistence/ ──► base
 *              │                                  │
 *              └──────────────┬───────────────────┘
 *                             ▼
 *                          domain/          (pur, ne dépend de rien)
 * ```
 *
 * **Une couche ne connaît que celle du dessous.** C'est la règle de la pile Python
 * (`docs/architecture/01`), reprise telle quelle, avec une couche de plus : `domain/`.
 *
 * Ce test existe parce qu'une règle d'architecture écrite dans un document n'est pas
 * une règle : elle est vraie le jour où on l'écrit, et fausse six mois plus tard. Le
 * projet Python fait déjà exactement cela pour l'agent, dont l'invariant d'import est
 * une propriété de sécurité — `tests/test_agent_worker.py` assert le graphe.
 *
 * ## Pourquoi `domain/` est pur
 *
 * `domain/` porte les calculs qui *décident* : l'empreinte d'un problème, le verdict
 * du gate, la chaîne d'intégrité de l'audit, les trois formats d'export. Ils ne
 * touchent ni la base, ni le réseau, ni NestJS. Trois conséquences :
 *
 * 1. ils se testent exhaustivement, ce qui est la seule façon de vérifier des règles
 *    dont une erreur ne lève aucune exception mais détruit du triage ;
 * 2. le même calcul sert l'API, l'ordonnanceur et l'interface — le verdict affiché
 *    est *celui* que rend le gate, pas un second qui lui ressemble ;
 * 3. ils survivraient à un changement d'ORM ou de framework, qui est précisément le
 *    genre d'évènement que ce projet vient de traverser.
 */

const SOURCE_ROOT = __dirname;

/** Les couches, de la plus basse à la plus haute. L'indice **est** le niveau. */
const LAYERS = ['domain', 'scanning', 'agent', 'persistence', 'repositories', 'services', 'api'] as const;
type Layer = (typeof LAYERS)[number];

/**
 * Ce qu'une couche a le droit d'importer, en plus de son propre niveau.
 *
 * `domain` n'a **rien** : c'est la contrainte qui a de la valeur, et la seule qu'un
 * relecteur pressé enfreindrait sans y penser (« juste une entité, pour le typage »).
 */
const ALLOWED: Record<Layer, readonly Layer[]> = {
    domain: [],
    /**
     * L'exécution d'un scan : disque, processus, conteneurs. Elle ne connaît que le
     * domaine — **ni base ni entités**, délibérément. C'est ce qui permet à un agent
     * distant, qui n'a qu'une socket Docker et un répertoire temporaire, de faire tourner
     * exactement ce code : s'il touchait à la persistance, il serait inexécutable là-bas.
     */
    scanning: ['domain'],
    /**
     * L'agent distant. Il ne connaît que le domaine et l'exécution — **ni base, ni
     * entités, ni NestJS**.
     *
     * Ce n'est pas une contrainte de style : un agent qui aurait une connexion à la base
     * aurait aussi besoin d'`ENCRYPTION_KEY`, c'est-à-dire de quoi déchiffrer *toutes* les
     * clés de déploiement que Zanshin détient. La propriété de sécurité qui justifie son
     * existence est précisément ce qu'il n'a pas, et une règle vérifiée vaut mieux qu'une
     * intention consignée dans un README.
     */
    agent: ['scanning', 'domain'],
    persistence: ['domain'],
    repositories: ['persistence', 'domain'],
    services: ['scanning', 'repositories', 'persistence', 'domain'],
    api: ['services', 'scanning', 'repositories', 'persistence', 'domain']
};

/** Les paquets qu'une couche n'a pas le droit de connaître. */
const FORBIDDEN_PACKAGES: Partial<Record<Layer, readonly string[]>> = {
    // Un calcul pur qui importerait TypeORM ne serait plus testable sans base, et un
    // qui importerait NestJS ne serait plus réutilisable hors du serveur.
    domain: ['typeorm', '@nestjs/', 'pg', 'ioredis', 'express'],
    // Une entité décrit une table ; l'injection de dépendances n'est pas son affaire.
    persistence: ['@nestjs/common', '@nestjs/core', 'express'],
    // La liste qui compte : ce sont les paquets par lesquels un accès à la base
    // arriverait, et le point d'un agent est de ne pas en avoir.
    agent: ['typeorm', 'pg', 'mysql2', '@nestjs/']
};

/**
 * Un `*.module.ts` est du câblage : c'est *le* fichier dont le rôle est de connaître
 * NestJS et d'assembler ce que la couche expose. L'exempter n'affaiblit pas la règle,
 * qui vise le contenu de la couche — entités, calculs, dépôts.
 *
 * `domain/` n'a pas d'exemption parce qu'il n'a pas de module : ce sont des fonctions
 * pures, il n'y a rien à injecter. Un `domain/*.module.ts` serait le signe que la
 * couche a cessé d'être pure, et le test doit le dire.
 */
const WIRING_FILE = /\.module\.ts$/;
const LAYERS_WITH_WIRING: readonly Layer[] = ['persistence', 'repositories', 'services', 'api'];

function sourceFiles(directory: string): string[] {
    const found: string[] = [];
    for (const entry of readdirSync(directory)) {
        const path = join(directory, entry);
        if (statSync(path).isDirectory()) found.push(...sourceFiles(path));
        else if (entry.endsWith('.ts')) found.push(path);
    }
    return found;
}

function layerOf(path: string): Layer | null {
    const segment = relative(SOURCE_ROOT, path).split('/')[0];
    return (LAYERS as readonly string[]).includes(segment) ? (segment as Layer) : null;
}

function importsOf(path: string): string[] {
    const source = readFileSync(path, 'utf8');
    return [...source.matchAll(/(?:^|\n)\s*import\s[^;]*?from\s+'([^']+)'/g)].map((match) => match[1]);
}

/** Résout un import relatif en couche cible, ou `null` s'il reste dans la sienne. */
function targetLayer(fromPath: string, specifier: string): Layer | null {
    if (!specifier.startsWith('.')) return null;
    const resolved = join(fromPath, '..', specifier);
    return layerOf(resolved);
}

describe('règle de couches', () => {
    const files = sourceFiles(SOURCE_ROOT).filter((path) => layerOf(path) !== null);

    it('trouve bien des fichiers à vérifier', () => {
        // Une erreur de chemin rendrait ce test vert sans rien vérifier — c'est le
        // mode de panne d'un test d'architecture.
        expect(files.length).toBeGreaterThan(5);
        expect(new Set(files.map(layerOf)).size).toBeGreaterThan(1);
    });

    it("aucune couche n'importe une couche au-dessus d'elle", () => {
        const violations: string[] = [];
        for (const path of files) {
            const from = layerOf(path)!;
            for (const specifier of importsOf(path)) {
                const to = targetLayer(path, specifier);
                if (to === null || to === from) continue;
                if (!ALLOWED[from].includes(to)) {
                    violations.push(`${relative(SOURCE_ROOT, path)} importe ${to}/ (${specifier}) — ${from}/ ne peut pas`);
                }
            }
        }
        expect(violations).toEqual([]);
    });

    it('le domaine ne dépend d’aucun framework ni d’aucun pilote', () => {
        const violations: string[] = [];
        for (const [layer, packages] of Object.entries(FORBIDDEN_PACKAGES) as [Layer, readonly string[]][]) {
            for (const path of files.filter((file) => layerOf(file) === layer)) {
                // Les specs ont le droit d'importer un harnais de test.
                if (path.endsWith('.spec.ts')) continue;
                if (WIRING_FILE.test(path) && LAYERS_WITH_WIRING.includes(layer)) continue;
                for (const specifier of importsOf(path)) {
                    const forbidden = packages.find((name) => specifier === name || specifier.startsWith(name));
                    if (forbidden) violations.push(`${relative(SOURCE_ROOT, path)} importe « ${specifier} » — interdit dans ${layer}/`);
                }
            }
        }
        expect(violations).toEqual([]);
    });

    it("le domaine n'a pas de module NestJS, parce qu'il n'a rien à injecter", () => {
        const modules = files.filter((path) => layerOf(path) === 'domain' && WIRING_FILE.test(path));
        expect(modules.map((path) => relative(SOURCE_ROOT, path))).toEqual([]);
    });

    it('chaque fichier de src/ appartient à une couche', () => {
        // Sans quoi la règle se contourne en posant le fichier à la racine.
        const orphans = sourceFiles(SOURCE_ROOT)
            .filter((path) => layerOf(path) === null)
            .map((path) => relative(SOURCE_ROOT, path))
            // Le point d'entrée et le module racine assemblent les couches : ils sont
            // au-dessus de toutes, donc dans aucune.
            .filter((path) => !['main.ts', 'app.module.ts', 'architecture.spec.ts'].includes(path));
        expect(orphans).toEqual([]);
    });
});
