import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import { ContainerService } from './services/container.service';
import { ContainerController } from './controllers/container.controller';
import { Container } from './entities/container.entity';
import { Scan } from '../repository/entities/scan.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([Container, Scan]),
    BullModule.registerQueue({
      name: 'scan-queue',
    }),
  ],
  controllers: [ContainerController],
  providers: [ContainerService],
  exports: [ContainerService],
})
export class ContainerModule {}
