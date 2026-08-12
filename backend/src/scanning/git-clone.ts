import { execFile } from 'node:child_process';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { validateRepositoryUrl } from '../domain/targets/git-url';

const run = promisify(execFile);

/**
 * Le clone d'un dépôt à scanner.
 *
 * C'est le point où une **URL fournie par un opérateur** et une **clé privée** se
 * rencontrent, sous un processus qui va exécuter git. Trois précautions, chacune pour une
 * raison précise :
 *
 * 1. **L'URL est revalidée ici**, alors qu'elle l'a déjà été à la saisie. Des lignes
 *    antérieures à cette validation existent en base, et une URL non vérifiée qui atteint
 *    `git clone` est une exécution de code arbitraire — `ext::` fait exécuter une commande
 *    par git lui-même.
 * 2. **`execFile` et non `exec`** : les arguments sont un tableau, jamais une ligne de
 *    commande à interpréter par un shell. Sans cela, un nom de branche contenant un
 *    point-virgule suffirait.
 * 3. **La clé privée vit dans un fichier temporaire en 0600, supprimé dans un `finally`.**
 *    Elle ne passe ni par la ligne de commande — visible dans `ps` de tout le système —
 *    ni par une variable d'environnement héritée par les processus enfants.
 */

/** Profondeur du clone. Un scan regarde l'arbre courant, pas l'histoire. */
const CLONE_DEPTH = 1;

/**
 * `StrictHostKeyChecking=accept-new` et non `no`.
 *
 * `no` accepte *toute* clé d'hôte, y compris une clé qui a changé — c'est-à-dire qu'il
 * désactive la détection d'interception. `accept-new` accepte un hôte inconnu à la
 * première rencontre mais refuse un hôte dont la clé a changé, ce qui est le compromis
 * utile pour un service qui clone des dépôts qu'il n'a jamais vus.
 *
 * Le fichier de known_hosts est celui de l'espace de travail : partagé entre scans, il
 * ferait d'une première rencontre malheureuse un problème permanent.
 */
const SSH_OPTIONS = ['-o', 'StrictHostKeyChecking=accept-new', '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes'];

export class CloneError extends Error {
    constructor(
        message: string,
        readonly stderr: string
    ) {
        super(message);
    }
}

export interface CloneRequest {
    url: string;
    branch: string;
    /** La destination. Créée par le clone lui-même. */
    into: string;
    /** La clé privée en clair, ou `null` pour un dépôt public. */
    privateKey?: string | null;
    timeoutMs?: number;
}

export async function cloneRepository(request: CloneRequest): Promise<void> {
    const invalid = validateRepositoryUrl(request.url);
    if (invalid) throw new CloneError(`URL de dépôt refusée : ${invalid}`, '');

    const keyDirectory = request.privateKey ? await mkdtemp(join(tmpdir(), 'zanshin-key-')) : null;
    try {
        const environment: NodeJS.ProcessEnv = {
            ...process.env,
            // Aucune invite, jamais : sans cela un dépôt privé sans clé valable ferait
            // attendre le scan sur une demande de mot de passe que personne ne lira.
            GIT_TERMINAL_PROMPT: '0',
            GIT_ASKPASS: '/bin/false',
            // **Locale figée.** `explain()` reconnaît les échecs de git à ses messages, et
            // ces messages sont traduits : sur une machine en français, « Remote branch
            // not found » devient « La branche distante n'a pas été trouvée » et aucun
            // motif ne correspond plus. L'opérateur reçoit alors « le clone a échoué »
            // sans sa cause. Trouvé par un test, la machine de développement étant en
            // français — sur une CI en anglais, le défaut serait resté invisible.
            LC_ALL: 'C',
            LANGUAGE: 'C',
            LANG: 'C'
        };

        if (keyDirectory) {
            const keyPath = join(keyDirectory, 'id');
            await writeFile(keyPath, ensureTrailingNewline(request.privateKey!), { mode: 0o600 });
            // Le mode est posé à l'écriture *et* vérifié : un umask permissif rendrait le
            // fichier lisible, et ssh refuse alors la clé — avec un message qui parle de
            // permissions et non du scan.
            await chmod(keyPath, 0o600);
            environment.GIT_SSH_COMMAND = ['ssh', '-i', keyPath, ...SSH_OPTIONS, '-o', `UserKnownHostsFile=${join(keyDirectory, 'known_hosts')}`].join(' ');
        }

        await run(
            'git',
            [
                'clone',
                '--depth',
                String(CLONE_DEPTH),
                '--single-branch',
                '--branch',
                request.branch,
                // `--` sépare les options des opérandes : sans lui, une URL commençant par
                // un tiret serait lue comme une option de git.
                '--',
                request.url,
                request.into
            ],
            { env: environment, timeout: request.timeoutMs ?? 300_000, maxBuffer: 8 * 1024 * 1024 }
        );
    } catch (error) {
        const stderr = String((error as { stderr?: string }).stderr ?? '');
        throw new CloneError(explain(request, stderr), stderr);
    } finally {
        if (keyDirectory) await rm(keyDirectory, { recursive: true, force: true });
    }
}

/**
 * Traduit l'erreur de git en une phrase qui dit quoi faire.
 *
 * Le message brut de git est correct et inutilisable : « Permission denied (publickey) »
 * n'indique ni quel dépôt, ni que Zanshin dispose d'une clé, ni où la déclarer. L'erreur
 * arrive dans un journal d'agent, des heures après le geste qui l'a causée.
 */
function explain(request: CloneRequest, stderr: string): string {
    if (/Could not find remote branch|Remote branch .* not found/i.test(stderr)) {
        return `La branche « ${request.branch} » n'existe pas sur ${request.url}.`;
    }
    if (/Permission denied \(publickey\)|Could not read from remote repository/i.test(stderr)) {
        return request.privateKey
            ? `Authentification refusée par ${request.url}. La clé de déploiement associée est-elle bien déclarée chez le fournisseur ?`
            : `${request.url} demande une authentification. Attachez une clé SSH à ce dépôt.`;
    }
    if (/Host key verification failed/i.test(stderr)) {
        return `La clé d'hôte de ${request.url} a changé depuis le dernier clone. Vérifiez qu'il s'agit bien du même serveur avant de relancer.`;
    }
    if (/timed out|ETIMEDOUT/i.test(stderr)) {
        return `Le clone de ${request.url} a expiré. Le dépôt est-il joignable depuis cette machine ?`;
    }
    return `Le clone de ${request.url} a échoué.`;
}

/** ssh refuse une clé privée dont la dernière ligne n'est pas terminée. C'est le genre de
 *  détail qu'un copier-coller depuis un navigateur perd, et l'erreur qui en résulte parle
 *  de format invalide plutôt que de retour à la ligne manquant. */
function ensureTrailingNewline(key: string): string {
    return key.endsWith('\n') ? key : `${key}\n`;
}
