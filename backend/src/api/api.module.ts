import { Module } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { APP_GUARD } from '@nestjs/core';
import { PersistenceModule } from '../persistence/persistence.module';
import { IssueRepository } from '../repositories/issue.repository';
import { TargetRepository } from '../repositories/target.repository';
import { AuditLogRepository } from '../repositories/audit-log.repository';
import { ScanDispatcherService } from '../services/scan-dispatcher.service';
import { ScanIngestorService } from '../services/scan-ingestor.service';
import { ScanWorkerService } from '../services/scan-worker.service';
import { ScanRepository } from '../repositories/scan.repository';
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
import { AuditLogController } from './audit-log.controller';
import { AgentsController } from './agents.controller';
import { ApiKeyAuthService } from '../services/api-key-auth.service';
import { DashboardController } from './dashboard.controller';
import { ApiKeysController } from './api-keys.controller';
import { UsersController } from './users.controller';
import { SshKeysController } from './ssh-keys.controller';
import { EncryptionService } from '../services/encryption.service';
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
    controllers: [AuthController, IssuesController, GateController, ExportsController, QualityController, RepositoriesController, ContainersController, SshKeysController, UsersController, ApiKeysController, AuditLogController, DashboardController, AgentsController],
    providers: [
        AuthService,
        AuditLogService,
        // Construit par fabrique et non par injection : son constructeur prend des
        // secrets, que les tests fournissent directement. Le laisser à l'injection ferait
        // chercher à Nest un fournisseur pour « string ».
        { provide: EncryptionService, useFactory: () => new EncryptionService() },
        IssueTriageService,
        SessionCleanupService,
        IssueRepository,
        TargetRepository,
        AuditLogRepository,
        ApiKeyAuthService,
        ScanRepository,
        // Construits par fabrique : leurs constructeurs prennent des collaborateurs avec
        // des valeurs par défaut, que l'injection prendrait pour des dépendances à
        // résoudre — et pour lesquelles il n'existe aucun fournisseur.
        { provide: ScanIngestorService, useFactory: () => new ScanIngestorService() },

        // Le distributeur reçoit la source de données : il ouvre ses propres transactions,
        // courtes pour la réclamation et absentes pendant l'exécution.
        { provide: ScanDispatcherService, useFactory: (dataSource: DataSource) => new ScanDispatcherService(dataSource), inject: [DataSource] },
        ScanWorkerService,
        { provide: APP_GUARD, useClass: AuthGuard }
    ]
})
export class ApiModule {}
