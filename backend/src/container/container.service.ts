import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository as TypeOrmRepository } from 'typeorm';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { Container } from './entities/container.entity';
import { CreateContainerDto } from './dto/create-container.dto';
import { UpdateContainerDto } from './dto/update-container.dto';
import { Scan } from '../repository/entities/scan.entity';

@Injectable()
export class ContainerService {
  constructor(
    @InjectRepository(Container)
    private readonly containerModel: TypeOrmRepository<Container>,
    @InjectRepository(Scan)
    private readonly scanModel: TypeOrmRepository<Scan>,
    @InjectQueue('scan-queue') private readonly scanQueue: Queue,
  ) {}

  async create(createContainerDto: CreateContainerDto): Promise<Container> {
    if (createContainerDto.imageName && createContainerDto.imageName.includes(':')) {
      const parts = createContainerDto.imageName.split(':');
      createContainerDto.imageName = parts[0];
      // Only override tag if one was provided in the image name
      if (parts[1]) {
        createContainerDto.tag = parts[1];
      }
    }
    const container = this.containerModel.create(createContainerDto);
    return this.containerModel.save(container);
  }

  async findAll(): Promise<Container[]> {
    return this.containerModel.find({ relations: ['scans'] });
  }

  async findOne(id: number): Promise<Container> {
    const container = await this.containerModel.findOne({
      where: { id },
      relations: ['scans'],
    });
    if (!container) throw new NotFoundException(`Container with ID ${id} not found`);
    return container;
  }

  async update(id: number, updateContainerDto: UpdateContainerDto): Promise<Container> {
    const container = await this.findOne(id);
    Object.assign(container, updateContainerDto);
    return this.containerModel.save(container);
  }

  async remove(id: number): Promise<void> {
    const container = await this.findOne(id);
    await this.containerModel.remove(container);
  }

  async triggerRescan(id: number): Promise<Scan> {
    const container = await this.findOne(id);
    
    // Create a new scan record for the container
    const scan = this.scanModel.create({
      container,
      status: 'pending',
      branch: container.tag || 'latest', // Docker doesn't have branch, we use this field for tag
      subPath: '',
    });
    const savedScan = await this.scanModel.save(scan);

    // Add job to the queue
    await this.scanQueue.add(
      'scan-container',
      {
        scanId: savedScan.id,
        containerId: container.id,
        registry: container.registry,
        imageName: container.imageName,
        tag: container.tag || 'latest',
        isContainer: true
      },
      {
        removeOnComplete: true,
        removeOnFail: 100, // Keep last 100 failed jobs
      },
    );

    return savedScan;
  }

  async deleteScan(containerId: number, scanId: number): Promise<void> {
    const scan = await this.scanModel.findOne({ where: { id: scanId, containerId } });
    if (!scan) throw new NotFoundException('Scan not found');
    await this.scanModel.remove(scan);
  }
}
