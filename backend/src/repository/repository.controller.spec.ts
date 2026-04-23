import { Test, TestingModule } from '@nestjs/testing';
import { RepositoryController } from './repository.controller';
import { RepositoryService } from './repository.service';
import { CreateRepositoryDto } from './dto/create-repository.dto';
import { CreateVexDecisionDto } from './dto/create-vex-decision.dto';

describe('RepositoryController', () => {
  let controller: RepositoryController;
  let service: RepositoryService;

  const mockService = {
    create: jest.fn(),
    findAll: jest.fn(),
    findOne: jest.fn(),
    update: jest.fn(),
    remove: jest.fn(),
    triggerScan: jest.fn(),
    upsertVexDecision: jest.fn(),
    getVexDecisions: jest.fn(),
    exportOpenVex: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [RepositoryController],
      providers: [
        {
          provide: RepositoryService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<RepositoryController>(RepositoryController);
    service = module.get<RepositoryService>(RepositoryService);

    jest.clearAllMocks();
  });

  const mockResponse = () => {
    const res: any = {};
    res.setHeader = jest.fn().mockReturnValue(res);
    res.send = jest.fn().mockReturnValue(res);
    return res;
  };

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('create', () => {
    it('should call service.create with dto', async () => {
      const dto: CreateRepositoryDto = { url: 'https://github.com/test' };
      mockService.create.mockResolvedValue({ id: 1, ...dto });

      const result = await controller.create(dto);

      expect(service.create).toHaveBeenCalledWith(dto);
      expect(result.id).toEqual(1);
    });
  });

  describe('findAll', () => {
    it('should call service.findAll', async () => {
      mockService.findAll.mockResolvedValue([]);
      await controller.findAll();
      expect(service.findAll).toHaveBeenCalled();
    });
  });

  describe('triggerScan', () => {
    it('should call service.triggerScan', async () => {
      const branch = 'main';
      mockService.triggerScan.mockResolvedValue({ id: 101 });

      const result = await controller.triggerScan('1', branch);

      expect(service.triggerScan).toHaveBeenCalledWith(1, '', 'main');
      expect(result.id).toEqual(101);
    });
  });

  describe('VEX Endpoints', () => {
    it('should call upsertVexDecision', async () => {
      const dto: CreateVexDecisionDto = {
        vulnerabilityId: 'CVE-1',
        packageName: 'p',
        status: 'fixed',
        repositoryId: 1,
      };
      mockService.upsertVexDecision.mockResolvedValue({ id: 1, ...dto });

      const result = await controller.upsertVex('1', dto);

      expect(service.upsertVexDecision).toHaveBeenCalledWith(1, dto);
      expect(result.status).toEqual('fixed');
    });

    it('should call exportOpenVex', async () => {
      const res = mockResponse();
      mockService.exportOpenVex.mockResolvedValue({ doc: 'vex' });

      await controller.exportOpenVex('1', res);

      expect(service.exportOpenVex).toHaveBeenCalledWith(1);
      expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'application/json');
      expect(res.send).toHaveBeenCalledWith({ doc: 'vex' });
    });
  });
});
