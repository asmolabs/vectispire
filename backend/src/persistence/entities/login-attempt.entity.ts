import { Column, Entity, PrimaryColumn } from 'typeorm';
import { stringColumn, timestampColumn } from '../columns';

/**
 * Un échec de connexion, compté dans une fenêtre glissante.
 *
 * Une ligne par tentative plutôt qu'un compteur incrémenté : c'est ce qui rend la
 * fenêtre réellement glissante. Un compteur avec une date de réinitialisation offrirait
 * à un attaquant un pic gratuit au changement de fenêtre.
 *
 * `counterKey` porte les deux espaces de noms — `login:user:<identifiant>` et
 * `login:client:<jeton>` — parce que les deux compteurs se lisent de la même façon et
 * qu'une table par compteur n'apporterait rien.
 */
@Entity('login_attempt')
export class LoginAttempt {
    @PrimaryColumn({ type: 'uuid' })
    id!: string;

    @Column({ ...stringColumn(), name: 'counter_key' })
    counterKey!: string;

    @Column({ ...timestampColumn(), name: 'occurred_at' })
    occurredAt!: string;
}
