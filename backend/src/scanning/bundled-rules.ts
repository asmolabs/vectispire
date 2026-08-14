import { cp } from 'node:fs/promises';
import { join } from 'node:path';
import type { Workspace } from './workspace';

/**
 * Les règles que Zanshin embarque, posées dans l'espace de travail d'un scan.
 *
 * **Pourquoi copier plutôt que monter le répertoire d'origine.** Les chemins de volume
 * sont résolus par le *démon* Docker, pas par le processus qui l'appelle : quand Zanshin
 * tourne lui-même en conteneur avec la socket montée, un répertoire de son image est
 * invisible du conteneur frère. L'espace de travail est le seul chemin que les deux côtés
 * voient, en local comme sur un agent distant.
 *
 * **Pourquoi c'est un module à part et non une méthode privée du runner.** Deux scanners
 * en dépendent — Semgrep pour ses règles, gitleaks pour sa configuration — et les tests
 * d'intégration les exercent un par un, sans passer par le runner. Une méthode privée
 * aurait laissé les tests reconstruire ce placement à la main, donc diverger du chemin réel
 * le jour où il change.
 */

/** L'arbre embarqué, à côté de ce module — `semgrep/` et `gitleaks/`. */
const BUNDLED_RULES = join(__dirname, 'rules');

/**
 * Copie l'arbre embarqué dans `workspace.rules`.
 *
 * Appelée **avant tout scanner**, et non depuis l'étape qui en a l'usage le plus évident :
 * la configuration de gitleaks doit être en place même quand le SAST est désactivé, faute
 * de quoi l'outil retombe sur le `.gitleaks.toml` du dépôt analysé — c'est-à-dire que la
 * cible fournit les règles de son propre audit.
 */
export async function placeBundledRules(workspace: Workspace): Promise<void> {
    await cp(BUNDLED_RULES, workspace.rules, { recursive: true });
}
