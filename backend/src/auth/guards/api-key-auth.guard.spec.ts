import { Test, TestingModule } from '@nestjs/testing';
import { ApiKeyAuthGuard } from './api-key-auth.guard';
import { ApiKeyService } from '../api-key.service';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';

describe('ApiKeyAuthGuard', () => {
  let guard: ApiKeyAuthGuard;
  let service: ApiKeyService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ApiKeyAuthGuard,
        {
          provide: ApiKeyService,
          useValue: {
            validateKey: jest.fn(),
          },
        },
      ],
    }).compile();

    guard = module.get<ApiKeyAuthGuard>(ApiKeyAuthGuard);
    service = module.get<ApiKeyService>(ApiKeyService);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  it('should throw UnauthorizedException if API key is missing', async () => {
    const context = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: {},
          query: {},
        }),
      }),
    } as unknown as ExecutionContext;

    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
  });

  it('should return true if API key is valid', async () => {
    const mockUser = { id: 1, username: 'test' };
    (service.validateKey as jest.Mock).mockResolvedValue({ user: mockUser });

    const context = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { 'x-api-key': 'valid-key' },
          query: {},
        }),
      }),
    } as unknown as ExecutionContext;

    const result = await guard.canActivate(context);
    expect(result).toBe(true);
    expect((context.switchToHttp().getRequest() as any).user).toEqual(mockUser);
  });

  it('should throw UnauthorizedException if API key is invalid', async () => {
    (service.validateKey as jest.Mock).mockResolvedValue(null);

    const context = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { 'x-api-key': 'invalid-key' },
          query: {},
        }),
      }),
    } as unknown as ExecutionContext;

    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
  });
});
