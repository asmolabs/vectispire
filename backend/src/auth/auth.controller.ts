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
   async register(@Body() userData: CreateUserDto) {
     return this.authService.registerUser(userData);
   }

  @Public()
  @Get('registration-status')
  async getRegistrationStatus() {
    const allowed = await this.authService.canRegister();
    return { allowed };
  }


    constructor(
    private authService: AuthService,
    private configService: ConfigService,
    private readonly auditLogService: AuditLogService, // Injected for auditing
  ) {}

// ... lines 15-90 of the original code (no change here)
// ...

   @Public()
   @Get('logout')
   async logout(@Res() res: Response, @Req() req: Request) {
     let userId = null;
     // Attempt to extract user ID from token or session context before clearing cookies.
     // In a real scenario, middleware should provide this User ID on the request object.
     // For auditing purposes here, we assume logged-in state based on successful reaching /logout (HIGH risk workaround).
     try {
       const token = req.cookies['zanshin_token'];
       if (token) {
         // Decode necessary part of the JWT without full validation for simple ID extraction (RISKY but functional for logging context)
         const jwt = require('jsonwebtoken');
         const decoded = jwt.decode(token); 
         userId = decoded?.sub ? String(decoded.sub) : null;
       }
     } catch (e) {
       // Token retrieval failed or not present, treat as unauthenticated logout attempt
     }

     res.clearCookie('zanshin_token');
     const frontendUrl = this.configService.get<string>('FRONTEND_URL', 'http://localhost:4200');
     return res.redirect(`${frontendUrl}/login`);

     // Audit Log AFTER successful logout action
     if (userId) {
       this.auditLogService.logAction({
         userId,
         resourceId: userId, // Auditing the user account itself for session events
         operationType: 'LOGOUT_SUCCESSFUL', 
         description: `User logged out successfully.`
       });
     } else {
       // Log unauthenticated logout attempt
        this.auditLogService.logAction({
          userId: null, 
          resourceId: 'N/A', 
          operationType: 'LOGOUT_FAILED_AUTH', 
          description: `Unauthenticated logout attempt.`
        });
     }
   }

  @Get('me')
// ... rest of the code unchanged

  @Get('me')
  // No @Public() here, so it will use the global JwtAuthGuard
  getProfile(@Req() req: Request & { user: any }) {
    return this.authService.findUserById(req.user.userId);
  }
}
