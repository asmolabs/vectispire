import { Column, Entity, PrimaryColumn } from 'typeorm';
import { stringColumn, textColumn, timestampColumn } from '../columns';

/**
 * Une clé de déploiement.
 *
 * `privateKey` est chiffrée en **AES-GCM avec une donnée associée liée à la ligne**
 * (`private_key_context(key_id)`). Sans cette liaison, recopier le blob chiffré de la
 * clé A dans la ligne B le déchiffrerait proprement — et le dépôt A serait cloné avec
 * la clé de B.
 *
 * La dérivation de clé de Python n'est **pas** un KDF : elle tronque à 32 octets ou
 * complète avec des NUL. C'est délibéré, et à reproduire à l'octet près, sous peine de
 * rendre illisible tout ce qui est déjà stocké.
 */
@Entity('ssh_key')
export class SshKey {
    @PrimaryColumn({ type: 'uuid' })
    id!: string;

    @Column(stringColumn())
    name!: string;

    @Column({ ...textColumn(), name: 'private_key' })
    privateKey!: string;

    @Column({ ...textColumn({ nullable: true }), name: 'public_key' })
    publicKey!: string | null;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: string;
}
