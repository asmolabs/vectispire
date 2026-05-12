import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { ThrottlerModule } from '@nestjs/throttler';
import { AppController } from './controllers/app.controller';
import { AppService } from './services/app.service';
import { RepositoryModule } from './repository/repository.module';
import { Repository } from './repository/entities/repository.entity';
import { Scan } from './repository/entities/scan.entity';
import { VexDecision } from './repository/entities/vex-decision.entity';
import { SSHKey } from './repository/entities/ssh-key.entity';
import { AuditLog } from './repository/entities/audit-log.entity';
import { Container } from './container/entities/container.entity';
import { AuthModule } from './auth/auth.module';
import { User } from './auth/entities/user.entity';
import { ApiKey } from './auth/entities/api-key.entity';
import { ContainerModule } from './container/container.module';
import { SettingsModule } from './settings/settings.module';
import { Setting } from './settings/entities/setting.entity';
import { MailModule } from './mail/mail.module';
import { NotificationsModule } from './notifications/notifications.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    ScheduleModule.forRoot(),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: configService.get<any>('DB_TYPE', 'sqlite'),
        database: configService.get<string>('DB_NAME', 'database.sqlite'),
        entities: [Repository, Scan, VexDecision, SSHKey, User, ApiKey, Container, Setting, AuditLog],
        synchronize: configService.get<boolean>('DB_SYNCHRONIZE', true),
      }),
    }),

    BullModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        connection: {
          host: configService.get<string>('REDIS_HOST', 'localhost'),
          port: configService.get<number>('REDIS_PORT', 6379),
        },
      }),
    }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => [
        {
          ttl: config.get<number>('THROTTLE_TTL', 60000),
          limit: config.get<number>('THROTTLE_LIMIT', 10),
        },
      ],
    }),
    RepositoryModule,
    ContainerModule,
    AuthModule,
    SettingsModule,
    MailModule,
    NotificationsModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
