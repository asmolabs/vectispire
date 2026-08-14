import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { User } from '../persistence/entities';
import { hashPassword } from './password.service';

/** La longueur minimale d'un mot de passe d'amorçage. La même que partout ailleurs. */
const MIN_PASSWORD_LENGTH = 8;

/**
 * Le premier compte, créé au démarrage quand la table des utilisateurs est vide.
 *
 * **Il n'y a pas de page d'auto-inscription**, et c'est délibéré : une application de
 * sécurité qui laisse n'importe qui se créer un compte administrateur n'en est pas une. Il
 * faut donc un chemin pour le tout premier, et c'est celui-ci.
 *
 * **Documenté depuis le début, implémenté nulle part.** Le README, le guide de démarrage et
 * les variables d'environnement décrivaient `ZANSHIN_BOOTSTRAP_USERNAME` et son mot de
 * passe ; rien ne les lisait. Une installation neuve démarrait donc sans aucun moyen de se
 * connecter — trouvé en montant un plan de contrôle pour éprouver l'agent distant, pas par
 * un test.
 *
 * **Uniquement sur une table vide.** Les variables sont ignorées dès qu'un compte existe :
 * sans cette condition, elles deviendraient une porte dérobée permanente, réactivable en
 * redémarrant le processus avec la bonne variable.
 */
@Injectable()
export class BootstrapService implements OnApplicationBootstrap {
    private readonly logger = new Logger(BootstrapService.name);

    constructor(@InjectEntityManager() private readonly manager: EntityManager) {}

    async onApplicationBootstrap(): Promise<void> {
        await this.createFirstUser();
    }

    /** Rend le compte créé, ou `null` s'il n'y avait rien à faire. */
    async createFirstUser(manager: EntityManager = this.manager): Promise<User | null> {
        if ((await manager.count(User)) > 0) return null;

        const username = (process.env.ZANSHIN_BOOTSTRAP_USERNAME ?? '').trim();
        const password = process.env.ZANSHIN_BOOTSTRAP_PASSWORD ?? '';

        if (!username || !password) {
            // Averti et non fatal : un déploiement peut créer son premier compte
            // autrement. Mais le silence serait pire que tout — l'opérateur découvrirait le
            // problème devant un écran de connexion qu'aucun identifiant ne franchit.
            this.logger.warn(
                "Aucun compte n'existe et ZANSHIN_BOOTSTRAP_USERNAME / ZANSHIN_BOOTSTRAP_PASSWORD ne sont pas posées : " +
                    'personne ne pourra se connecter. Posez-les et redémarrez.'
            );
            return null;
        }

        if (password.length < MIN_PASSWORD_LENGTH) {
            this.logger.error(
                `ZANSHIN_BOOTSTRAP_PASSWORD fait moins de ${MIN_PASSWORD_LENGTH} caractères : le compte n'est pas créé. ` +
                    'Un premier compte est un SUPERUSER, et il ouvre tout le reste.'
            );
            return null;
        }

        const moment = now();
        const user = await manager.save(
            Object.assign(new User(), {
                username,
                email: null,
                password: hashPassword(password),
                displayName: null,
                avatarUrl: null,
                role: 'SUPERUSER',
                isActive: true,
                githubId: null,
                keycloakId: null,
                createdAt: moment,
                updatedAt: moment,
                // **Le mot de passe passe par une variable d'environnement**, donc par la
                // configuration du déploiement, les journaux d'orchestrateur et
                // l'historique du shell. Exiger son changement à la première connexion est
                // ce qui empêche cette valeur de rester le secret d'un compte SUPERUSER.
                mustChangePassword: true
            })
        );

        this.logger.log(`Compte SUPERUSER « ${username} » créé — changement de mot de passe exigé à la première connexion.`);
        return user;
    }
}
