import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SSHKey } from '../entities/ssh-key.entity';
import { CreateSSHKeyDto } from './dto/create-ssh-key.dto';
import { EncryptionService } from '../../common/encryption.service';
import * as crypto from 'crypto';
import { generateKeyPairSync } from 'crypto';

@Injectable()
export class SSHKeyService {
  constructor(
    @InjectRepository(SSHKey)
    private readonly sshKeyRepository: Repository<SSHKey>,
    private readonly encryptionService: EncryptionService,
  ) {}

  /**
   * Normalize a PEM key string to ensure it has proper line endings.
   * Handles keys pasted from UI that may have literal \n or missing newlines.
   */
  private normalizePrivateKey(rawKey: string): string {
    // Replace literal \n with real newlines (if user pasted escaped string)
    let key = rawKey.replace(/\\n/g, '\n');
    // Normalize line endings (CRLF → LF)
    key = key.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    // Trim surrounding whitespace
    key = key.trim();
    // Ensure it ends with a newline (required by OpenSSH)
    if (!key.endsWith('\n')) {
      key = key + '\n';
    }
    return key;
  }

  generateKeyPair() {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8', // OpenSSH-like PEM
        format: 'pem'
      }
    });

    return {
      id: crypto.randomUUID(),
      publicKey: publicKey.toString(),
      privateKey: privateKey.toString()
    };
  }

  async create(createSSHKeyDto: CreateSSHKeyDto): Promise<SSHKey> {
    // Determine the ID: use provided one or generate a new UUID
    const id = createSSHKeyDto.id || crypto.randomUUID();

    // Normalize the key format before storing
    const normalizedKey = this.normalizePrivateKey(createSSHKeyDto.privateKey);
    const encryptedPrivateKey = this.encryptionService.encrypt(normalizedKey);
    
    let publicKey = createSSHKeyDto.publicKey;
    if (!publicKey) {
      try {
        const privateKeyObj = crypto.createPrivateKey(normalizedKey);
        publicKey = crypto.createPublicKey(privateKeyObj)
          .export({ type: 'spki', format: 'pem' })
          .toString();
      } catch (err) {
        console.error('Failed to extract public key:', err);
      }
    }

    const sshKey = this.sshKeyRepository.create({
      ...createSSHKeyDto,
      id,
      privateKey: encryptedPrivateKey,
      publicKey: publicKey,
    });
    return this.sshKeyRepository.save(sshKey);
  }

  async findAll(): Promise<Partial<SSHKey>[]> {
    // Return id, name, publicKey and createdAt
    const keys = await this.sshKeyRepository.find({
      order: { createdAt: 'DESC' }
    });
    return keys.map(key => ({
      id: key.id,
      name: key.name,
      publicKey: key.publicKey,
      createdAt: key.createdAt,
    }));
  }

  async findOne(id: string): Promise<SSHKey> {
    const key = await this.sshKeyRepository.findOne({ where: { id } });
    if (!key) {
      throw new NotFoundException(`SSH Key with ID ${id} not found`);
    }
    return key;
  }

  async remove(id: string): Promise<void> {
    const result = await this.sshKeyRepository.delete(id);
    if (result.affected === 0) {
      throw new NotFoundException(`SSH Key with ID ${id} not found`);
    }
  }

  async getDecryptedKey(id: string): Promise<string> {
    const key = await this.findOne(id);
    const decrypted = this.encryptionService.decrypt(key.privateKey);
    // Normalize just in case the key was stored before the normalization fix
    return this.normalizePrivateKey(decrypted);
  }
}
