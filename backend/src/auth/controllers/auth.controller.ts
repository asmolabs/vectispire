import { Controller, Get, Post, Body, UseGuards, Req, Res } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { Request, Response } from 'express';
import { AuthService } from '../services/auth.service';
import { ConfigService } from '@nestjs/config';
import { Public } from '../decorators/public.decorator';
import { AuditLogService } from '../../repository/services/audit-log.service';
import { CreateUserDto } from '../dto/create-user.dto';
import * as jwt from 'jsonwebtoken';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
    private readonly auditLogService: AuditLogService,
  ) {}

  @Public()
  @Get('github')
  @UseGuards(AuthGuard('github'))
  async githubLogin() {
    // Redirects to GitHub
  }

  @Public()
  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  async githubCallback(@Req() req: Request, @Res() res: Response) {
    const { access_token } = await this.authService.login(req.user as any);
    const frontendUrl = this.configService.get<string>('FRONTEND_URL', 'http://localhost:4200');
    
    res.cookie('zanshin_token', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    return res.redirect(`${frontendUrl}/login`);
  }

  @Public()
  @Get('keycloak')
  @UseGuards(AuthGuard('keycloak'))
  async keycloakLogin() {
    // Redirects to Keycloak
  }

  @Public()
  @Get('keycloak/callback')
  @UseGuards(AuthGuard('keycloak'))
  async keycloakCallback(@Req() req: Request, @Res() res: Response) {
    const { access_token } = await this.authService.login(req.user as any);
    const frontendUrl = this.configService.get<string>('FRONTEND_URL', 'http://localhost:4200');
    
    res.cookie('zanshin_token', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    return res.redirect(`${frontendUrl}/login`);
  }

  @Public()
  @UseGuards(AuthGuard('local'))
  @Post('login')
  async login(@Req() req: Request, @Res() res: Response) {
    const { access_token, user } = await this.authService.login(req.user as any);
    
    res.cookie('zanshin_token', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    return res.json({ success: true, user });
  }

  @Public()
  @Post('register')
  async register(@Body() userData: CreateUserDto) {
    return this.authService.registerUser(userData);
  }

  @Public()
  @Get('registration-status')
  async getRegistrationStatus() {
    const allowed = await this.authService.isFirstUser();
    return { allowed };
  }

  @Public()
  @Get('logout')
  async logout(@Res() res: Response, @Req() req: Request) {
    let userId = null;
    try {
      const token = req.cookies['zanshin_token'];
      if (token) {
        const decoded = jwt.decode(token) as any;
        userId = decoded?.sub ? Number(decoded.sub) : null;
      }
    } catch (e) {
      // Token retrieval failed
    }

    res.clearCookie('zanshin_token');
    
    if (userId) {
      await this.auditLogService.logAction({
        userId,
        resourceId: String(userId),
        operationType: 'LOGOUT_SUCCESSFUL',
        description: `User logged out successfully.`,
      });
    } else {
      await this.auditLogService.logAction({
        userId: null,
        resourceId: 'N/A',
        operationType: 'LOGOUT_FAILED_AUTH',
        description: `Unauthenticated logout attempt.`,
      });
    }

    const frontendUrl = this.configService.get<string>('FRONTEND_URL', 'http://localhost:4200');
    return res.redirect(`${frontendUrl}/login`);
  }

  @Get('me')
  getProfile(@Req() req: Request & { user: any }) {
    return this.authService.findUserById(req.user.userId);
  }
}
