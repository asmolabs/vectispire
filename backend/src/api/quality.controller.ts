import { Controller, Get } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { Repository as GitRepository, STATE_OPEN } from '../persistence/entities';
import { IssueRepository } from '../repositories/issue.repository';
import { TYPE_QUALITY } from '../domain/issues/types';

/** Le type que les scanners produisent pour ce qui touche à l'écriture du code. */


/**
 * L'agrégation qui rend l'écran Qualité utile.
 *
 * **Si cette page n'était que `/issues?type=quality`, elle ne mériterait pas
 * d'exister** — ce serait un filtre. Elle agrège donc sur des axes que le backlog
 * n'offre pas : les règles les plus fréquentes, les fichiers les plus touchés, les
 * dépôts les plus denses. Devant un backlog de qualité à quatre chiffres, « huit règles
 * font soixante-dix pour cent de la dette » est le seul cadrage actionnable.
 */
@Controller('api/v1/quality')
export class QualityController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly issues: IssueRepository = new IssueRepository()
    ) {}

    @Get('overview')
    async overview() {
        const [total, byRule, byFile, byTarget] = await Promise.all([
            this.issues.countFiltered(this.manager, { state: STATE_OPEN, type: TYPE_QUALITY }),
            this.issues.countOpenGrouped(this.manager, TYPE_QUALITY, 'rule'),
            this.issues.countOpenGrouped(this.manager, TYPE_QUALITY, 'file'),
            this.issues.countOpenGrouped(this.manager, TYPE_QUALITY, 'target')
        ]);

        return {
            openCount: total,
            ruleCount: byRule.length,
            fileCount: byFile.length,
            topRules: byRule,
            topFiles: byFile,
            // Le regroupement rend un `repo_id` ; l'afficher tel quel obligerait la
            // personne à traduire une clé étrangère de tête. Résolu ici plutôt que par
            // une jointure : la liste fait huit lignes, et une jointure dans la requête
            // groupée forcerait à grouper aussi sur le nom.
            topTargets: await this.withRepositoryNames(byTarget)
        };
    }

    private async withRepositoryNames(rows: { label: string | null; count: number }[]) {
        const ids = rows.map((row) => Number(row.label)).filter((id) => Number.isFinite(id));
        if (ids.length === 0) return rows;

        const repositories = await this.manager.findByIds(GitRepository, ids);
        const nameById = new Map(repositories.map((repository) => [repository.id, repository.name || repository.url]));
        return rows.map((row) => ({ ...row, label: nameById.get(Number(row.label)) ?? row.label }));
    }
}
