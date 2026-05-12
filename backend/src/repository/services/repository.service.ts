import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { Repository as TypeOrmRepository } from 'typeorm';
import { CreateRepositoryDto } from '../../repository/dto/create-repository.dto';
import { UpdateRepositoryDto } from '../../repository/dto/update-repository.dto';
import { Repository } from '../../repository/entities/repository.entity';
import { Scan } from '../../repository/entities/scan.entity';
import { VexDecision } from '../../repository/entities/vex-decision.entity';
import { CreateVexDecisionDto } from '../../repository/dto/create-vex-decision.dto';

@Injectable()
export class RepositoryService {
  private readonly logger = new Logger(RepositoryService.name);

  constructor(
    @InjectRepository(Repository)
    private readonly repoModel: TypeOrmRepository<Repository>,
    @InjectRepository(Scan)
    private readonly scanModel: TypeOrmRepository<Scan>,
    @InjectRepository(VexDecision)
    private readonly vexModel: TypeOrmRepository<VexDecision>,
    @InjectQueue('scan-queue')
    private readonly scanQueue: Queue,
  ) {}

  async create(createRepositoryDto: CreateRepositoryDto) {
    const subPath = createRepositoryDto.subPath || '';
    let repo = await this.repoModel.findOne({
      where: { 
        url: createRepositoryDto.url,
        branch: createRepositoryDto.branch,
        subPath: subPath
      },
    });

    if (!repo) {
      const newRepo = this.repoModel.create({
        url: createRepositoryDto.url,
        branch: createRepositoryDto.branch,
        subPath: subPath,
        name: createRepositoryDto.name,
        sshKeyId: createRepositoryDto.sshKeyId,
      });
      repo = await this.repoModel.save(newRepo);
      this.logger.log(`Created new repository entry for ${repo.name || repo.url} [${repo.branch}${repo.subPath ? ':' + repo.subPath : ''}]`);
    } else {
      let updated = false;
      if (createRepositoryDto.sshKeyId && repo.sshKeyId !== createRepositoryDto.sshKeyId) {
        repo.sshKeyId = createRepositoryDto.sshKeyId;
        updated = true;
      }
      if (createRepositoryDto.name && repo.name !== createRepositoryDto.name) {
        repo.name = createRepositoryDto.name;
        updated = true;
      }
      if (updated) {
        repo = await this.repoModel.save(repo);
        this.logger.log(`Updated repository ${repo.name || repo.url} [${repo.branch}${repo.subPath ? ':' + repo.subPath : ''}]`);
      }
      this.logger.log(`Reusing existing repository entry for ${repo.name || repo.url} [${repo.branch}${repo.subPath ? ':' + repo.subPath : ''}]`);
    }

    await this.triggerScan(repo.id, repo.url, repo.branch, repo.subPath);

    return repo;
  }

  async triggerScan(repositoryId: number, repoUrl: string, branch: string, subPath?: string) {
    let sshKeyId = null;
    let actualSubPath = subPath;
    if (!repoUrl) {
      const repo = await this.repoModel.findOne({ where: { id: repositoryId } });
      if (!repo) throw new Error('Repository not found');
      repoUrl = repo.url;
      sshKeyId = repo.sshKeyId;
      actualSubPath = repo.subPath;
    } else {
        const repo = await this.repoModel.findOne({ where: { id: repositoryId } });
        sshKeyId = repo?.sshKeyId;
        if (actualSubPath === undefined) {
          actualSubPath = repo?.subPath || '';
        }
    }
    const newScan = this.scanModel.create({
      branch: branch,
      subPath: actualSubPath,
      status: 'pending',
      repoId: repositoryId,
    });
    const savedScan = await this.scanModel.save(newScan);

    // Add job to BullMQ queue for each branch scan
    await this.scanQueue.add(
      'analyze',
      {
        scanId: savedScan.id,
        repoUrl: repoUrl,
        branch: branch,
        subPath: actualSubPath,
        sshKeyId: sshKeyId,
      },
      {
        attempts: 3,
        backoff: { type: 'exponential', delay: 5000 },
      },
    );

    this.logger.log(`Added scan job for repo ${repositoryId} branch ${branch} path ${actualSubPath} (Scan ID: ${savedScan.id})`);
    return savedScan;
  }

  findAll() {
    return this.repoModel.find({
      relations: ['scans'],
      order: { scans: { createdAt: 'DESC' } },
    });
  }

  findOne(id: number) {
    return this.repoModel.findOne({
      where: { id },
      relations: ['scans', 'vexDecisions'],
      order: { scans: { createdAt: 'DESC' } },
    });
  }

  update(id: number, updateRepositoryDto: UpdateRepositoryDto) {
    return this.repoModel.update(id, updateRepositoryDto);
  }

  remove(id: number) {
    return this.repoModel.delete(id);
  }

  removeScan(scanId: number) {
    return this.scanModel.delete(scanId);
  }

  async upsertVexDecision(repoId: number, dto: CreateVexDecisionDto) {
    const repo = await this.repoModel.findOne({ where: { id: repoId } });
    if (!repo) throw new NotFoundException('Repository not found');

    let decision = await this.vexModel.findOne({
      where: {
        repositoryId: repoId,
        vulnerabilityId: dto.vulnerabilityId,
        packageName: dto.packageName,
      },
    });

    if (decision) {
      Object.assign(decision, dto);
      return this.vexModel.save(decision);
    } else {
      const newDecision = this.vexModel.create({
        ...dto,
        repositoryId: repoId,
      });
      return this.vexModel.save(newDecision);
    }
  }

  async getVexDecisions(repoId: number) {
    return this.vexModel.find({
      where: { repositoryId: repoId },
    });
  }

  async exportOpenVex(repoId: number) {
    const repo = await this.repoModel.findOne({
      where: { id: repoId },
      relations: ['vexDecisions'],
    });

    if (!repo) throw new NotFoundException('Repository not found');

    const openVexDoc = {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      '@id': `https://zanshin.io/vex/repo-${repoId}-${Date.now()}`,
      author: 'Zanshin Security Scanner',
      role: 'Document Creator',
      timestamp: new Date().toISOString(),
      version: 1,
      statements: repo.vexDecisions.map((d) => ({
        vulnerability: {
          name: d.vulnerabilityId,
        },
        products: [
          {
            '@id': d.purl || `pkg:generic/${d.packageName}`,
          },
        ],
        status: d.status,
        justification: d.justification || undefined,
        impact_statement: d.comment || undefined,
        action_statement: d.response || undefined,
      })),
    };

    return openVexDoc;
  }
}
