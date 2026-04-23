import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ScanProcessor } from './scan.processor';
import { Scan } from './entities/scan.entity';
import { NotificationGateway } from './notification.gateway';
import { SSHKeyService } from './ssh-key/ssh-key.service';
import * as child_process from 'child_process';
import * as fs from 'fs';
import { Job } from 'bullmq';

// Mock child_process and fs at the top
jest.mock('child_process', () => ({
  exec: jest.fn(),
  execFile: jest.fn(),
}));

jest.mock('fs');
const mockedExecFile = child_process.execFile as unknown as jest.Mock;
const mockedFs = fs as jest.Mocked<typeof fs>;

describe('ScanProcessor', () => {
  let processor: ScanProcessor;
  let scanModel: any;
  let notificationGateway: any;
  let sshKeyService: any;

  const mockScanModel = {
    update: jest.fn(),
  };

  const mockNotificationGateway = {
    sendScanUpdate: jest.fn(),
  };

  const mockSSHKeyService = {
    getDecryptedKey: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ScanProcessor,
        {
          provide: getRepositoryToken(Scan),
          useValue: mockScanModel,
        },
        {
          provide: NotificationGateway,
          useValue: mockNotificationGateway,
        },
        {
          provide: SSHKeyService,
          useValue: mockSSHKeyService,
        },
      ],
    }).compile();

    processor = module.get<ScanProcessor>(ScanProcessor);
    scanModel = module.get(getRepositoryToken(Scan));
    notificationGateway = module.get(NotificationGateway);
    sshKeyService = module.get(SSHKeyService);

    jest.clearAllMocks();
    
    // Default mocks for FS and child_process
    mockedFs.existsSync.mockReturnValue(true);
    mockedFs.mkdirSync.mockImplementation(() => '');
    mockedFs.rmSync.mockImplementation(() => '');
    mockedFs.unlinkSync.mockImplementation(() => '');
    mockedFs.writeFileSync.mockImplementation(() => '');
  });

  it('should be defined', () => {
    expect(processor).toBeDefined();
  });

  describe('process', () => {
    const mockJob = {
      data: {
        scanId: 1,
        repoUrl: 'https://github.com/test/repo',
        branch: 'main',
      },
    } as Job;

    it('should complete successfully and update scan with summary', async () => {
      const mockSbom = { artifacts: [] };
      const mockCves = {
        matches: [
          { vulnerability: { severity: 'High' } },
          { vulnerability: { severity: 'Medium' } },
          { vulnerability: { severity: 'High' } },
        ],
      };

      // Mock exec results (git clone, syft, grype)
      mockedExecFile.mockImplementation((file: string, args: string[], options: any, callback: any) => {
        if (args.join(' ').includes('syft')) {
          callback(null, { stdout: JSON.stringify(mockSbom), stderr: '' });
        } else if (args.join(' ').includes('grype')) {
          callback(null, { stdout: JSON.stringify(mockCves), stderr: '' });
        } else {
          callback(null, { stdout: '', stderr: '' });
        }
      });

      mockedFs.readFileSync.mockImplementation((path: string) => {
        if (path.includes('sbom.json')) return JSON.stringify(mockSbom);
        if (path.includes('cves.json')) return JSON.stringify(mockCves);
        return '';
      });

      await processor.process(mockJob);

      // Verify status updates
      expect(scanModel.update).toHaveBeenCalledWith(1, { status: 'scanning' });
      expect(notificationGateway.sendScanUpdate).toHaveBeenCalledWith(1, 'scanning');

      // Verify tool executions
      expect(mockedExecFile).toHaveBeenCalledTimes(3); // clone, syft, grype
      
      // Verify final update with summary
      expect(scanModel.update).toHaveBeenCalledWith(1, expect.objectContaining({
        status: 'completed',
        findingsCount: 3,
        summary: {
            critical: 0,
            high: 2,
            medium: 1,
            low: 0,
            negligible: 0,
            unknown: 0,
            total: 3
        }
      }));
      expect(notificationGateway.sendScanUpdate).toHaveBeenCalledWith(1, 'completed');
    });

    it('should handle failure and set status to failed', async () => {
      // Mock git clone failure
      mockedExecFile.mockImplementation((file: string, args: string[], options: any, callback: any) => {
        if (args.includes('clone')) {
          callback(new Error('Clone failed'), { stdout: '', stderr: '' });
        } else {
          callback(null, { stdout: '', stderr: '' });
        }
      });

      await expect(processor.process(mockJob)).rejects.toThrow('Clone failed');

      expect(scanModel.update).toHaveBeenCalledWith(1, expect.objectContaining({ status: 'failed' }));
      expect(notificationGateway.sendScanUpdate).toHaveBeenCalledWith(1, 'failed');
      
      // Verify cleanup regardless of failure
      expect(mockedFs.rmSync).toHaveBeenCalled();
    });
  });
});
