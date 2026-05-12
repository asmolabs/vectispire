import { Module, forwardRef } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { APP_GUARD } from '@nestjs/core';
import { RepositoryModule } from '../repository/repository.module';
import { AuthService } from './services/auth.service';
import { AuthController } from './controllers/auth.controller';
import { UsersController } from './controllers/users.controller';
import { User } from './entities/user.entity';
import { ApiKey } from './entities/api-key.entity';
import { GithubStrategy } from './strategies/github.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { KeycloakStrategy } from './strategies/keycloak.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ApiKeyService } from './services/api-key.service';
import { ApiKeyController } from './controllers/api-key.controller';
import { ApiKeyAuthGuard } from './guards/api-key-auth.guard';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, ApiKey]),
    forwardRef(() => RepositoryModule),
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '1d' },
      }),
    }),
  ],
  providers: [
    AuthService, 
    ApiKeyService,
    GithubStrategy, 
    JwtStrategy, 
    KeycloakStrategy,
    LocalStrategy,
    ApiKeyAuthGuard,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
  ],
  controllers: [AuthController, UsersController, ApiKeyController],
  exports: [AuthService, ApiKeyService],
})
export class AuthModule {}

