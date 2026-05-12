import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { getQueueToken } from '@nestjs/bullmq';
import { RepositoryService } from '../services/repository.service';
import { Repository } from './entities/repository.entity';
import { Scan } from './entities/scan.entity';
import { VexDecision } from './entities/vex-decision.entity';
import { NotFoundException } from '@nestjs/common';

describe('RepositoryService', () => {
  let service: RepositoryService;
  let repoModel: any;
  let scanModel: any;
  let vexModel: any;
  let scanQueue: any;

  const mockRepoModel = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    find: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  };

  const mockScanModel = {
    create: jest.fn(),
    save: jest.fn(),
  };

  const mockVexModel = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    find: jest.fn(),
  };

  const mockScanQueue = {
    add: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RepositoryService,
        {
          provide: getRepositoryToken(Repository),
          useValue: mockRepoModel,
        },
        {
          provide: getRepositoryToken(Scan),
          useValue: mockScanModel,
        },
        {
          provide: getRepositoryToken(VexDecision),
          useValue: mockVexModel,
        },
        {
          provide: getQueueToken('scan-queue'),
          useValue: mockScanQueue,
        },
      ],
    }).compile();

    service = module.get<RepositoryService>(RepositoryService);
    repoModel = module.get(getRepositoryToken(Repository));
    scanModel = module.get(getRepositoryToken(Scan));
    vexModel = module.get(getRepositoryToken(VexDecision));
    scanQueue = module.get(getQueueToken('scan-queue'));

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create a new repo if not exists and trigger scan', async () => {
      const dto = { url: 'https://github.com/test/repo', branch: 'main' };
      repoModel.findOne.mockResolvedValue(null);
      repoModel.create.mockReturnValue({ id: 1, url: dto.url, branch: dto.branch });
      repoModel.save.mockResolvedValue({ id: 1, url: dto.url, branch: dto.branch });
      scanModel.create.mockReturnValue({ id: 101 });
      scanModel.save.mockResolvedValue({ id: 101 });

      const result = await service.create(dto);

      expect(repoModel.findOne).toHaveBeenCalled();
      expect(repoModel.create).toHaveBeenCalledWith({ url: dto.url, branch: dto.branch, name: undefined, sshKeyId: undefined });
      expect(repoModel.save).toHaveBeenCalled();
      expect(scanQueue.add).toHaveBeenCalledTimes(1); 
      expect(result).toEqual({ id: 1, url: dto.url, branch: dto.branch });
    });

    it('should reuse existing repo and trigger scan', async () => {
      const dto = { url: 'https://github.com/test/repo', branch: 'main' };
      const existingRepo = { id: 1, url: dto.url, branch: 'main' };
      repoModel.findOne.mockResolvedValue(existingRepo);
      scanModel.create.mockReturnValue({ id: 101 });
      scanModel.save.mockResolvedValue({ id: 101 });

      const result = await service.create(dto as any);

      expect(repoModel.create).not.toHaveBeenCalled();
      expect(scanQueue.add).toHaveBeenCalledTimes(1); // default 'main'
      expect(result).toEqual(existingRepo);
    });
  });

  describe('triggerScan', () => {
    it('should create a scan and add to queue', async () => {
      const scanData = { id: 101, branch: 'main', status: 'pending', repositoryId: 1 };
      scanModel.create.mockReturnValue(scanData);
      scanModel.save.mockResolvedValue(scanData);

      const result = await service.triggerScan(1, 'https://github.com/test/repo', 'main');

      expect(scanModel.create).toHaveBeenCalledWith({
        branch: 'main',
        status: 'pending',
        repositoryId: 1,
      });
      expect(scanQueue.add).toHaveBeenCalledWith(
        'analyze',
        { scanId: 101, repoUrl: 'https://github.com/test/repo', branch: 'main' },
        expect.any(Object),
      );
      expect(result).toEqual(scanData);
    });
  });

  describe('upsertVexDecision', () => {
    it('should throw NotFoundException if repo doesn\'t exist', async () => {
      repoModel.findOne.mockResolvedValue(null);
      await expect(service.upsertVexDecision(1, {} as any)).rejects.toThrow(NotFoundException);
    });

    it('should update existing decision', async () => {
      repoModel.findOne.mockResolvedValue({ id: 1 });
      const existingDecision = { id: 50, status: 'open' };
      vexModel.findOne.mockResolvedValue(existingDecision);
      vexModel.save.mockResolvedValue({ ...existingDecision, status: 'fixed' });

      const result = await service.upsertVexDecision(1, { status: 'fixed', repositoryId: 1 } as any);

      expect(vexModel.save).toHaveBeenCalled();
      expect(result.status).toEqual('fixed');
    });

    it('should create new decision', async () => {
      repoModel.findOne.mockResolvedValue({ id: 1 });
      vexModel.findOne.mockResolvedValue(null);
      vexModel.create.mockReturnValue({ id: 51 });
      vexModel.save.mockResolvedValue({ id: 51, status: 'fixed' });

      const result = await service.upsertVexDecision(1, { status: 'fixed', repositoryId: 1 } as any);

      expect(vexModel.create).toHaveBeenCalled();
      expect(vexModel.save).toHaveBeenCalled();
      expect(result.id).toEqual(51);
    });
  });

  describe('exportOpenVex', () => {
    it('should generate OpenVEX document', async () => {
      const repo = {
        id: 1,
        vexDecisions: [
          {
            vulnerabilityId: 'CVE-2021-1234',
            packageName: 'test-pkg',
            status: 'not_affected',
            justification: 'code_not_present',
          },
        ],
      };
      repoModel.findOne.mockResolvedValue(repo);

      const result = await service.exportOpenVex(1);

      expect(result['@context']).toBeDefined();
      expect(result.statements).toHaveLength(1);
      expect(result.statements[0].vulnerability.name).toBe('CVE-2021-1234');
    });
  });
});
