import { Test, TestingModule } from '@nestjs/testing';
import { ExternalScanController } from './external-scan.controller';
import { RepositoryService } from './repository.service';
import { ApiKeyAuthGuard } from '../auth/guards/api-key-auth.guard';
import { ApiKeyService } from '../auth/api-key.service';
import { ExternalScanDto } from './dto/external-scan.dto';

describe('ExternalScanController', () => {
  let controller: ExternalScanController;
  let service: RepositoryService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ExternalScanController],
      providers: [
        {
          provide: RepositoryService,
          useValue: {
            create: jest.fn(),
          },
        },
        {
          provide: ApiKeyService,
          useValue: {
            validateKey: jest.fn(),
          },
        },
      ],
    })
      .overrideGuard(ApiKeyAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<ExternalScanController>(ExternalScanController);
    service = module.get<RepositoryService>(RepositoryService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should trigger external scan', async () => {
    const dto: ExternalScanDto = {
      url: 'https://github.com/user/repo.git',
      branch: 'main',
      subPath: '',
      sshKeyId: 'some-uuid',
    };

    const mockRepo = { id: 1, ...dto };
    (service.create as jest.Mock).mockResolvedValue(mockRepo);

    const result = await controller.triggerExternalScan(dto);
    expect(result).toEqual(mockRepo);
    expect(service.create).toHaveBeenCalledWith({
      url: dto.url,
      branch: dto.branch,
      subPath: dto.subPath,
      sshKeyId: dto.sshKeyId,
    });
  });
});
