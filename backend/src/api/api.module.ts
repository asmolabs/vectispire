import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { PersistenceModule } from '../persistence/persistence.module';
import { IssueRepository } from '../repositories/issue.repository';
import { TargetRepository } from '../repositories/target.repository';
import { AuditLogService } from '../services/audit-log.service';
import { AuthService } from '../services/auth.service';
import { IssueTriageService } from '../services/issue-triage.service';
import { SessionCleanupService } from '../services/session-cleanup.service';
import { AuthController } from './auth.controller';
import { AuthGuard } from './auth.guard';
import { ExportsController } from './exports.controller';
import { GateController } from './gate.controller';
import { IssuesController } from './issues.controller';
import { ContainersController } from './containers.controller';
import { QualityController } from './quality.controller';
import { RepositoriesController } from './repositories.controller';

/**
 * La couche HTTP.
 *
 * **`AuthGuard` est enregistrée globalement**, et c'est le choix qui compte : une garde
 * posée route par route protège ce qu'on a pensé à annoter. Le défaut devient donc
 * « authentifié », et une route publique doit le déclarer avec `@Public()`. Oublier une
 * annotation ferme alors une route au lieu de l'ouvrir — l'erreur se remarque tout de
 * suite, au lieu d'exposer quelque chose en silence.
 */
@Module({
    imports: [PersistenceModule],
    controllers: [AuthController, IssuesController, GateController, ExportsController, QualityController, RepositoriesController, ContainersController],
    providers: [
        AuthService,
        AuditLogService,
        IssueTriageService,
        SessionCleanupService,
        IssueRepository,
        TargetRepository,
        { provide: APP_GUARD, useClass: AuthGuard }
    ]
})
export class ApiModule {}
