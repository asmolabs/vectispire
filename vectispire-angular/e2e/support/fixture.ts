import { DatabaseSync } from 'node:sqlite';

/**
 * Un constat réel dans la base de la suite navigateur.
 *
 * <p><b>Sans lui, deux cas de `roles.spec.ts` ne pouvaient pas échouer.</b> Ils affirment qu'un
 * auditeur ne se voit proposer aucun bouton de triage, et la base de la suite n'a jamais contenu
 * la moindre vulnérabilité : la liste s'affichait vide, le compte de boutons valait zéro pour
 * tout le monde, et l'assertion passait aussi bien avec la garde qu'en la retirant. C'est le même
 * défaut que les deux assertions sur `body` du fichier d'audit, écrit dans l'autre sens.
 *
 * <p><b>Écrit en SQL, et non par une route.</b> Une vulnérabilité naît d'un scan remonté par un
 * agent ; la fabriquer par le vrai chemin demanderait une clé d'agent et une charge de résultats
 * complète pour obtenir une ligne dont seule l'existence compte ici. Ce que ces cas éprouvent est
 * l'accord entre le rôle et l'écran, pas l'ingestion.
 */
/**
 * Rend son budget de tentatives au compteur anti-force-brute.
 *
 * <p><b>La campagne partageait un contrôle de sécurité, et se le disputait.</b>
 * {@code LoginThrottle} bloque après cinq échecs par compte et vingt par client sur quinze
 * minutes glissantes, et ce sont des constantes de compilation. La variable que le nocturne pose
 * à 200 relève le seau par adresse de {@code LoginRateLimitFilter} — un compteur réel, mais un
 * autre : elle ne touche pas celui-ci. Dix-sept cas qui se connectent épuisent donc ce budget-là,
 * et le cas qui reçoit le {@code 429} n'est pas celui qui l'a dépensé : les échecs tombaient au
 * hasard de l'ordre d'exécution, sur des suites sans rapport.
 *
 * <p><b>Remettre le compteur à zéro plutôt qu'affaiblir le seuil.</b> Un seuil d'authentification
 * que l'environnement peut relever est une commande d'affaiblissement livrée avec le produit ;
 * la base de la campagne, elle, appartient à la campagne. `auth.spec.ts` éprouve précisément ce
 * contrôle, et cet appel lui rend un budget propre à chaque cas au lieu de le lui retirer.
 */
export function resetLoginThrottle(): void {
    withDatabase((db) => db.prepare('delete from t_login_attempt').run());
}

/** L'unique endroit qui sait où vit la base de la campagne, et qui la referme. */
function withDatabase<T>(work: (db: DatabaseSync) => T): T {
    const url = process.env.VECTISPIRE_DB_URL ?? 'jdbc:sqlite:/tmp/e2e.db';
    const file = url.replace(/^jdbc:sqlite:/, '');

    // **Bruyant plutôt que silencieux.** Renoncer sans rien dire rendrait aux cas la vacuité que
    // ces fonctions existent pour leur retirer : ils repasseraient au vert en n'éprouvant rien.
    if (url === file) {
        throw new Error(`VECTISPIRE_DB_URL n'est pas une base SQLite : ${url}`);
    }

    const db = new DatabaseSync(file);
    try {
        return work(db);
    } finally {
        db.close();
    }
}

export function seedOneIssue(): void {
    withDatabase((db) => {
        const seen = db.prepare('select count(*) as n from t_issue').get() as { n: number };
        if (seen.n > 0) return;

        db.prepare(
            `insert into t_repository (url, branch, name) values (?, ?, ?)`
        ).run('https://example.invalid/seed.git', 'main', 'seed repository');
        const repo = db.prepare('select last_insert_rowid() as id').get() as { id: number };

        const now = Date.now();
        db.prepare(
            `insert into t_issue (repo_id, fingerprint, type, identifier, package_name,
                                  package_version, severity, cvss_score, state,
                                  first_seen_at, last_seen_at, description, fix_versions)
             -- Les versions correctrices sont dans le désordre, et « 2.9.0 » passe après
             -- « 2.17.1 » dans un tri de chaînes : c'est ce que le plan doit ne pas conseiller.
             values (?, ?, 'vulnerability', 'CVE-2021-44228', 'log4j-core',
                     '2.14.1', 'critical', 10.0, 'open', ?, ?, ?, '2.9.0, 2.17.1, 2.12.4')`
        ).run(repo.id, 'seed-fingerprint-0000', now, now,
              "Constat d'amorçage : la liste doit contenir une ligne pour que l'absence de bouton veuille dire quelque chose.");
    });
}
