import { Controller, Get, Post, Body, UseGuards, Req, Res } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { Public } from './decorators/public.decorator';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
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
  async register(@Body() userData: any) {
    return this.authService.registerUser(userData);
  }

  @Public()
  @Get('registration-status')
  async getRegistrationStatus() {
    const allowed = await this.authService.canRegister();
    return { allowed };
  }


  @Public()
  @Get('logout')
  async logout(@Res() res: Response) {
    res.clearCookie('zanshin_token');
    const frontendUrl = this.configService.get<string>('FRONTEND_URL', 'http://localhost:4200');
    return res.redirect(`${frontendUrl}/login`);
  }

  @Get('me')
  // No @Public() here, so it will use the global JwtAuthGuard
  getProfile(@Req() req: Request & { user: any }) {
    return this.authService.findUserById(req.user.userId);
  }
}
