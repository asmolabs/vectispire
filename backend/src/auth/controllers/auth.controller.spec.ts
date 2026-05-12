import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: AuthService;
  let configService: ConfigService;

  const mockAuthService = {
    login: jest.fn(),
    findUserById: jest.fn(),
  };

  const mockConfigService = {
    get: jest.fn().mockImplementation((key: string, defaultValue: string) => {
        if (key === 'FRONTEND_URL') return defaultValue || 'http://localhost:4200';
        return null;
    }),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get<AuthService>(AuthService);
    configService = module.get<ConfigService>(ConfigService);
    
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('githubCallback', () => {
    it('should redirect to frontend and set cookie', async () => {
      const mockReq = { user: { id: 1, username: 'testuser' } };
      const mockRes = {
        cookie: jest.fn(),
        redirect: jest.fn(),
      };
      
      mockAuthService.login.mockResolvedValue({ access_token: 'mock_token' });

      await controller.githubCallback(mockReq as any, mockRes as any);

      expect(mockAuthService.login).toHaveBeenCalledWith(mockReq.user);
      expect(mockRes.cookie).toHaveBeenCalledWith('zanshin_token', 'mock_token', expect.any(Object));
      expect(mockRes.redirect).toHaveBeenCalledWith('http://localhost:4200/login');
    });
  });

  describe('logout', () => {
    it('should clear cookie and redirect', async () => {
      const mockRes = {
        clearCookie: jest.fn(),
        redirect: jest.fn(),
      };

      await controller.logout(mockRes as any);

      expect(mockRes.clearCookie).toHaveBeenCalledWith('zanshin_token');
      expect(mockRes.redirect).toHaveBeenCalledWith('http://localhost:4200/login');
    });
  });

  describe('getProfile', () => {
    it('should return user from service', async () => {
      const mockReq = { user: { userId: 1 } };
      const user = { id: 1, username: 'testuser' };
      mockAuthService.findUserById.mockResolvedValue(user);

      const result = await controller.getProfile(mockReq as any);

      expect(result).toEqual(user);
      expect(mockAuthService.findUserById).toHaveBeenCalledWith(1);
    });
  });
});
