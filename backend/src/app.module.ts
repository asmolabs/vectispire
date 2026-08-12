import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { ApiModule } from './api/api.module';
import { PersistenceModule } from './persistence/persistence.module';

/**
 * Le module racine : il assemble les couches, il n'en est aucune.
 *
 * La règle de dépendance entre couches est vérifiée par `architecture.spec.ts`, qui
 * exclut explicitement ce fichier et `main.ts` — tous deux sont au-dessus de toutes
 * les couches, donc dans aucune.
 */
@Module({
    imports: [ConfigModule.forRoot({ isGlobal: true }), ScheduleModule.forRoot(), PersistenceModule, ApiModule]
})
export class AppModule {}
