import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-openidconnect';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth.service';

@Injectable()
export class KeycloakStrategy extends PassportStrategy(Strategy, 'keycloak') {
  private configService: ConfigService;
  private authService: AuthService;

  constructor(
    configService: ConfigService,
    authService: AuthService,
  ) {
    const issuer = configService.get<string>('KEYCLOAK_URL') + '/realms/' + configService.get<string>('KEYCLOAK_REALM');
    const clientID = configService.get<string>('KEYCLOAK_CLIENT_ID');
    const clientSecret = configService.get<string>('KEYCLOAK_CLIENT_SECRET');
    const callbackURL = configService.get<string>('KEYCLOAK_CALLBACK_URL');

    if (!clientID || !clientSecret || !callbackURL || !configService.get<string>('KEYCLOAK_URL')) {
        // Fallback for development if not provided
        super({
            issuer: issuer || 'http://localhost:8080/realms/master',
            authorizationURL: (configService.get<string>('KEYCLOAK_URL') || 'http://localhost:8080') + '/realms/' + (configService.get<string>('KEYCLOAK_REALM') || 'master') + '/protocol/openid-connect/auth',
            tokenURL: (configService.get<string>('KEYCLOAK_URL') || 'http://localhost:8080') + '/realms/' + (configService.get<string>('KEYCLOAK_REALM') || 'master') + '/protocol/openid-connect/token',
            userInfoURL: (configService.get<string>('KEYCLOAK_URL') || 'http://localhost:8080') + '/realms/' + (configService.get<string>('KEYCLOAK_REALM') || 'master') + '/protocol/openid-connect/userinfo',
            clientID: clientID || 'temporary_client',
            clientSecret: clientSecret || 'temporary_secret',
            callbackURL: callbackURL || 'http://localhost:3000/auth/keycloak/callback',
            scope: ['email', 'profile'],
        });
    } else {
        super({
            issuer,
            authorizationURL: issuer + '/protocol/openid-connect/auth',
            tokenURL: issuer + '/protocol/openid-connect/token',
            userInfoURL: issuer + '/protocol/openid-connect/userinfo',
            clientID,
            clientSecret,
            callbackURL,
            scope: ['email', 'profile'],
        });
    }
    this.configService = configService;
    this.authService = authService;
  }

  async validate(issuer: string, profile: any, done: Function) {
    const { id, displayName, emails, username } = profile;
    const user = await this.authService.validateKeycloakUser({
      id,
      displayName,
      emails,
      username,
    });
    return done(null, user);
  }
}
