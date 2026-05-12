import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { User } from './entities/user.entity';

describe('AuthService', () => {
  let service: AuthService;
  let userRepository: any;
  let jwtService: JwtService;

  const mockUser = {
    id: 1,
    username: 'testuser',
    email: 'test@example.com',
    githubId: '12345',
  };

  const mockUserRepository = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
  };

  const mockJwtService = {
    sign: jest.fn().mockReturnValue('mock_token'),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(User),
          useValue: mockUserRepository,
        },
        {
          provide: JwtService,
          useValue: mockJwtService,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userRepository = module.get(getRepositoryToken(User));
    jwtService = module.get(JwtService);
    
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validateUser', () => {
    const githubProfile = {
      id: '12345',
      username: 'testuser',
      emails: [{ value: 'test@example.com' }],
      photos: [{ value: 'avatar_url' }],
      displayName: 'Test User',
    };

    it('should return existing user if found by githubId', async () => {
      mockUserRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.validateUser(githubProfile);

      expect(result).toEqual(mockUser);
      expect(userRepository.findOne).toHaveBeenCalledWith({ where: { githubId: '12345' } });
      expect(userRepository.save).toHaveBeenCalled();
    });

    it('should create new user if not found', async () => {
      mockUserRepository.findOne.mockResolvedValue(null);
      mockUserRepository.create.mockReturnValue(mockUser);
      mockUserRepository.save.mockResolvedValue(mockUser);

      const result = await service.validateUser(githubProfile);

      expect(result).toEqual(mockUser);
      expect(userRepository.create).toHaveBeenCalled();
      expect(userRepository.save).toHaveBeenCalled();
    });
  });

  describe('login', () => {
    it('should return access token and user info', async () => {
      const result = await service.login(mockUser as User);

      expect(result).toEqual({
        access_token: 'mock_token',
        user: mockUser,
      });
      expect(jwtService.sign).toHaveBeenCalledWith({
        username: mockUser.username,
        sub: mockUser.id,
      });
    });
  });

  describe('findUserById', () => {
    it('should return user if found', async () => {
      mockUserRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.findUserById(1);

      expect(result).toEqual(mockUser);
      expect(userRepository.findOne).toHaveBeenCalledWith({ where: { id: 1 } });
    });
  });
});
