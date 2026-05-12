import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-github2';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../services/auth.service';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  private configService: ConfigService;
  private authService: AuthService;

  constructor(
    configService: ConfigService,
    authService: AuthService,
  ) {
    const clientID = configService.get<string>('GITHUB_CLIENT_ID');
    const clientSecret = configService.get<string>('GITHUB_CLIENT_SECRET');
    const callbackURL = configService.get<string>('GITHUB_CALLBACK_URL');

    if (!clientID || !clientSecret || !callbackURL) {
      // In production, these should be required. For development, we might use placeholders.
      // However, passport-github2 requires them to be strings.
      super({
        clientID: clientID || 'temporary_id',
        clientSecret: clientSecret || 'temporary_secret',
        callbackURL: callbackURL || 'http://localhost:3000/auth/github/callback',
        scope: ['user:email'],
      });
    } else {
      super({
        clientID,
        clientSecret,
        callbackURL,
        scope: ['user:email'],
      });
    }
    this.configService = configService;
    this.authService = authService;
  }

  async validate(accessToken: string, refreshToken: string, profile: any, done: Function) {
    const user = await this.authService.validateUser(profile);
    return done(null, user);
  }
}
