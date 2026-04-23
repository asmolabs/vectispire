import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ApiKey } from './entities/api-key.entity';
import * as crypto from 'crypto';

@Injectable()
export class ApiKeyService {
  constructor(
    @InjectRepository(ApiKey)
    private readonly apiKeyRepository: Repository<ApiKey>,
  ) {}

  async create(userId: number, name: string): Promise<{ apiKey: ApiKey; rawKey: string }> {
    const rawKey = `zns_${crypto.randomBytes(24).toString('hex')}`;
    const hash = this.hashKey(rawKey);
    
    const apiKey = this.apiKeyRepository.create({
      name,
      key: hash,
      userId,
    });
    
    const saved = await this.apiKeyRepository.save(apiKey);
    return { apiKey: saved, rawKey };
  }

  async validateKey(rawKey: string): Promise<ApiKey | null> {
    const hash = this.hashKey(rawKey);
    const apiKey = await this.apiKeyRepository.findOne({
      where: { key: hash },
      relations: ['user'],
    });

    if (apiKey) {
      apiKey.lastUsedAt = new Date();
      await this.apiKeyRepository.save(apiKey);
    }

    return apiKey;
  }

  async findAllForUser(userId: number): Promise<ApiKey[]> {
    return this.apiKeyRepository.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });
  }

  async remove(id: string, userId: number): Promise<void> {
    const result = await this.apiKeyRepository.delete({ id, userId });
    if (result.affected === 0) {
      throw new UnauthorizedException('API key not found or access denied');
    }
  }

  private hashKey(key: string): string {
    return crypto.createHash('sha256').update(key).digest('hex');
  }
}
