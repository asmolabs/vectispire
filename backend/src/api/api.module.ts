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
import { BootstrapService } from '../services/bootstrap.service';
import { IssueTriageService } from '../services/issue-triage.service';
import { SessionCleanupService } from '../services/session-cleanup.service';
import { AuthController } from './auth.controller';
import { AuthGuard } from './auth.guard';
import { ExportsController } from './exports.controller';
import { GateController } from './gate.controller';
import { IssuesController } from './issues.controller';
import { ContainersController } from './containers.controller';
import { AuditLogController } from './audit-log.controller';
import { ScansController } from './scans.controller';
import { AgentsAdminController } from './agents-admin.controller';
import { AgentsController } from './agents.controller';
import { ApiKeyAuthService } from '../services/api-key-auth.service';
import { DashboardController } from './dashboard.controller';
import { ApiKeysController } from './api-keys.controller';
import { UsersController } from './users.controller';
import { SshKeysController } from './ssh-keys.controller';
import { EncryptionService } from '../services/encryption.service';
import { EnrichmentService } from '../services/enrichment.service';
import { EolService } from '../services/eol.service';
import { LeaderElectionService } from '../services/leader-election.service';
import { LicenseService } from '../services/license.service';
import { MaintenanceService } from '../services/maintenance.service';
import { NotificationService } from '../services/notification.service';
import { OutboxService } from '../services/outbox.service';
import { RetentionService } from '../services/retention.service';
import { SchedulerService } from '../services/scheduler.service';
import { SettingsService } from '../services/settings.service';
import { TicketService } from '../services/ticket.service';
import { TicketSweepService } from '../services/ticket-sweep.service';
import { QualityController } from './quality.controller';
import { RepositoriesController } from './repositories.controller';
import { SettingsController } from './settings.controller';

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
    controllers: [AuthController, IssuesController, GateController, ExportsController, QualityController, RepositoriesController, ContainersController, SshKeysController, UsersController, ApiKeysController, AuditLogController, DashboardController, AgentsController, AgentsAdminController, ScansController, SettingsController],
    providers: [
        AuthService,
        AuditLogService,
        BootstrapService,
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
        SettingsService,
        // Par fabrique : le second paramètre est une fonction, que l'injection prendrait
        // pour un fournisseur à résoudre — le même piège que pour `EncryptionService`.
        { provide: EnrichmentService, useFactory: (settings: SettingsService) => new EnrichmentService(settings), inject: [SettingsService] },
        // L'ingesteur reçoit l'enrichissement ici, et nulle part ailleurs : c'est le seul
        // chemin où un scan doit appeler le réseau.
        { provide: EolService, useFactory: (settings: SettingsService) => new EolService(settings), inject: [SettingsService] },
        { provide: NotificationService, useFactory: (settings: SettingsService) => new NotificationService(settings), inject: [SettingsService] },
        OutboxService,
        LicenseService,
        {
            provide: ScanIngestorService,
            useFactory: (
                enrichment: EnrichmentService,
                eol: EolService,
                notifications: NotificationService,
                outbox: OutboxService,
                licenses: LicenseService
            ) => new ScanIngestorService(undefined, enrichment, eol, notifications, outbox, licenses),
            inject: [EnrichmentService, EolService, NotificationService, OutboxService, LicenseService]
        },

        // Le distributeur reçoit la source de données : il ouvre ses propres transactions,
        // courtes pour la réclamation et absentes pendant l'exécution.
        {
            provide: ScanDispatcherService,
            useFactory: (dataSource: DataSource, settings: SettingsService) =>
                new ScanDispatcherService(dataSource, undefined, undefined, undefined, undefined, settings),
            inject: [DataSource, SettingsService]
        },
        ScanWorkerService,
        RetentionService,
        // Le jeton du gestionnaire est chiffré au repos : le service reçoit donc le
        // chiffrement, comme les clés SSH.
        {
            provide: TicketService,
            useFactory: (settings: SettingsService, encryption: EncryptionService) => new TicketService(settings, encryption),
            inject: [SettingsService, EncryptionService]
        },
        TicketSweepService,
        MaintenanceService,
        LeaderElectionService,
        SchedulerService,
        { provide: APP_GUARD, useClass: AuthGuard }
    ]
})
export class ApiModule {}
