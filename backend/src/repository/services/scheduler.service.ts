import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository as TypeOrmRepository } from 'typeorm';
import { Repository } from '../../repository/entities/repository.entity';
import { RepositoryService } from './repository.service';
import { Container } from '../../container/entities/container.entity';
import { ContainerService } from '../../container/services/container.service';
import cronParser from 'cron-parser';

@Injectable()
export class SchedulerService {
  private readonly logger = new Logger(SchedulerService.name);

  constructor(
    @InjectRepository(Repository)
    private readonly repoModel: TypeOrmRepository<Repository>,
    private readonly repositoryService: RepositoryService,
    @InjectRepository(Container)
    private readonly containerModel: TypeOrmRepository<Container>,
    private readonly containerService: ContainerService,
  ) {}

  @Cron(CronExpression.EVERY_MINUTE)
  async handleCron() {
    const now = new Date();
    // We check for the current minute. Some crons might fire exactly at the beginning of the minute.
    // To avoid missing or double triggers, we consider the interval [now, now + 1m]
    
    const allScheduled = await this.repoModel.createQueryBuilder('repo')
      .where('repo.scanIntervalMinutes > 0 OR repo.scanCron IS NOT NULL')
      .getMany();

    for (const repo of allScheduled) {
      let shouldTrigger = false;

      // 1. Check Interval Logic
      if (repo.scanIntervalMinutes > 0) {
        const intervalMs = repo.scanIntervalMinutes * 60 * 1000;
        const lastScan = repo.lastScheduledScanAt ? new Date(repo.lastScheduledScanAt).getTime() : 0;
        if (now.getTime() - lastScan >= intervalMs) {
          shouldTrigger = true;
          this.logger.log(`Interval trigger for ${repo.url} (${repo.scanIntervalMinutes}m)`);
        }
      }

      // 2. Check Cron Logic (if not already triggered by interval)
      if (!shouldTrigger && repo.scanCron) {
        try {
          const interval = cronParser.parse(repo.scanCron);
          const nextExecution = interval.prev().toDate(); // Get the last time it SHOULD have run
          
          const lastScan = repo.lastScheduledScanAt ? new Date(repo.lastScheduledScanAt) : new Date(0);
          
          // If the last time it should have run is after our last recorded scan, trigger it
          if (nextExecution > lastScan) {
            shouldTrigger = true;
            this.logger.log(`Cron trigger for ${repo.url} (${repo.scanCron})`);
          }
        } catch (err) {
          this.logger.error(`Invalid cron for repo ${repo.id}: ${repo.scanCron}`);
        }
      }

      if (shouldTrigger) {
        try {
          await this.repositoryService.triggerScan(repo.id, repo.url, repo.branch, repo.subPath);
          repo.lastScheduledScanAt = now;
          await this.repoModel.save(repo);
        } catch (error) {
          this.logger.error(`Failed to trigger scheduled scan for repo ${repo.id}: ${error.message}`);
        }
      }
    }
    const allScheduledContainers = await this.containerModel.createQueryBuilder('container')
      .where('container.scanIntervalMinutes > 0 OR container.scanCron IS NOT NULL')
      .getMany();

    for (const container of allScheduledContainers) {
      let shouldTrigger = false;

      // 1. Check Interval Logic
      if (container.scanIntervalMinutes > 0) {
        const intervalMs = container.scanIntervalMinutes * 60 * 1000;
        const lastScan = container.lastScheduledScanAt ? new Date(container.lastScheduledScanAt).getTime() : 0;
        if (now.getTime() - lastScan >= intervalMs) {
          shouldTrigger = true;
          this.logger.log(`Interval trigger for container ${container.imageName} (${container.scanIntervalMinutes}m)`);
        }
      }

      // 2. Check Cron Logic (if not already triggered by interval)
      if (!shouldTrigger && container.scanCron) {
        try {
          const interval = cronParser.parse(container.scanCron);
          const nextExecution = interval.prev().toDate();
          
          const lastScan = container.lastScheduledScanAt ? new Date(container.lastScheduledScanAt) : new Date(0);
          
          if (nextExecution > lastScan) {
            shouldTrigger = true;
            this.logger.log(`Cron trigger for container ${container.imageName} (${container.scanCron})`);
          }
        } catch (err) {
          this.logger.error(`Invalid cron for container ${container.id}: ${container.scanCron}`);
        }
      }

      if (shouldTrigger) {
        try {
          await this.containerService.triggerRescan(container.id);
          container.lastScheduledScanAt = now;
          await this.containerModel.save(container);
        } catch (error) {
          this.logger.error(`Failed to trigger scheduled scan for container ${container.id}: ${error.message}`);
        }
      }
    }
  }
}
