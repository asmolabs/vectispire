import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SSHKey } from '../entities/ssh-key.entity';
import { SSHKeyService } from './ssh-key.service';
import { SSHKeyController } from './ssh-key.controller';
import { EncryptionService } from '../../common/encryption.service';

@Module({
  imports: [TypeOrmModule.forFeature([SSHKey])],
  controllers: [SSHKeyController],
  providers: [SSHKeyService, EncryptionService],
  exports: [SSHKeyService],
})
export class SSHKeyModule {}
