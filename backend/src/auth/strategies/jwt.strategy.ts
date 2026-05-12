import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../services/auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    const secretOrKey = configService.get<string>('JWT_SECRET');
    if (!secretOrKey) {
      // For development, provide a fallback to avoid crash, but log warning
      console.warn('JWT_SECRET is not defined, using fallback secret');
    }
    super({
      jwtFromRequest: (req: any) => {
        let token = null;
        if (req && req.cookies) {
          token = req.cookies['zanshin_token'];
        }
        return token || ExtractJwt.fromAuthHeaderAsBearerToken()(req);
      },
      ignoreExpiration: false,
      secretOrKey: secretOrKey || 'fallback_secret',
    });
  }

  async validate(payload: any) {
    const user = await this.authService.findUserById(payload.sub);
    
    if (!user || !user.isActive) {
      throw new UnauthorizedException('Votre compte est inactif ou en attente de validation.');
    }
    
    return { userId: user.id, username: user.username, role: user.role };
  }
}

