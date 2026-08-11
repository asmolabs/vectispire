import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { intColumn, stringColumn, textColumn, timestampColumn } from '../columns';

/**
 * Le résultat d'une revue de code par modèle local, au plus un par scan.
 *
 * Écrit dans une table à part et non sur le scan, parce que la fonctionnalité est
 * optionnelle : un scan exécuté alors qu'elle était désactivée n'a simplement pas de
 * ligne ici.
 *
 * Un échec — Ollama injoignable, modèle en erreur — est enregistré sur la ligne
 * elle-même (`status`, `error`) plutôt que propagé : il ne doit jamais transformer un
 * scan déjà terminé en échec. Une réponse qui ne s'analyse pas produit tout de même une
 * ligne complète avec le texte brut, le modèle n'ayant pas rendu la forme demandée
 * n'étant pas un échec de la revue.
 */
@Entity('ai_review_result')
export class AiReviewResult {
    @PrimaryGeneratedColumn({ type: 'integer' })
    id!: number;

    @Column({ ...intColumn(), name: 'scan_id' })
    scanId!: number;

    @Column(stringColumn())
    model!: string;

    @Column(textColumn())
    prompt!: string;

    @Column(textColumn({ nullable: true }))
    response!: string | null;

    @Column(stringColumn(50))
    status!: string;

    @Column(stringColumn(500, { nullable: true }))
    error!: string | null;

    @Column({ ...timestampColumn(), name: 'created_at' })
    createdAt!: Date;
}
