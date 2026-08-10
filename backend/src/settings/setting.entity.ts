import { Column, Entity, PrimaryColumn } from 'typeorm';
import { stringColumn } from '../database/columns';

/**
 * Un réglage, en clé/valeur texte.
 *
 * Volontairement sans typage ni schéma : les réglages sont lus par les services qui
 * les possèdent, chacun connaissant le sien et sa valeur par défaut. C'est ce qui
 * permet d'ajouter un réglage sans migration — et ce qui impose que chaque lecteur
 * gère l'absence de la clé.
 */
@Entity('setting')
export class Setting {
    @PrimaryColumn({ type: 'character varying', length: 255 })
    key!: string;

    @Column(stringColumn(255, { nullable: true }))
    value!: string | null;
}
