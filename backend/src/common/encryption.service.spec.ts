import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { EncryptionService } from './encryption.service';

describe('EncryptionService', () => {
  let service: EncryptionService;
  let configService: ConfigService;

  const mockEncryptionKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  const mockConfigService = {
    get: jest.fn().mockReturnValue(mockEncryptionKey),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EncryptionService,
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    service = module.get<EncryptionService>(EncryptionService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should encrypt and decrypt text correctly', () => {
    const plainText = 'ZanshinSecurity123!';
    const encrypted = service.encrypt(plainText);
    
    expect(encrypted).toBeDefined();
    expect(encrypted).toContain(':');
    
    const decrypted = service.decrypt(encrypted);
    expect(decrypted).toEqual(plainText);
  });

  it('should throw error for invalid encryption key length', () => {
    const localMockConfig = {
      get: jest.fn().mockReturnValue('short_key'),
    };
    
    expect(() => {
      new EncryptionService(localMockConfig as any);
    }).toThrow('ENCRYPTION_KEY must be a 64-character hex string (32 bytes)');
  });

  it('should throw error for invalid encrypted format during decryption', () => {
    expect(() => {
      service.decrypt('invalid-format');
    }).toThrow('Invalid encrypted data format');
  });
});
