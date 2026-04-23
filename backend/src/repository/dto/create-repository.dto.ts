import { Matches, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateRepositoryDto {
  @IsNotEmpty()
  @Matches(/^(https?:\/\/|git@|ssh:\/\/)([^\s]+)$/, { 
    message: 'Please provide a valid Git URL (HTTPS or SSH)' 
  })
  url: string;

  @IsOptional()
  @IsString()
  name?: string;

  @IsNotEmpty()
  @IsString()
  branch: string;

  @IsOptional()
  @IsString()
  subPath?: string;

  @IsOptional()
  @IsString()
  sshKeyId?: string;

  @IsOptional()
  scanIntervalMinutes?: number;

  @IsOptional()
  @IsString()
  scanCron?: string;
}
