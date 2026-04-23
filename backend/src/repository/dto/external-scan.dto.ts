import { IsNotEmpty, IsOptional, IsString, Matches } from 'class-validator';

export class ExternalScanDto {
  @IsNotEmpty()
  @Matches(/^(https?:\/\/|git@|ssh:\/\/)([^\s]+)$/, { 
    message: 'Please provide a valid Git URL (HTTPS or SSH)' 
  })
  url: string;

  @IsOptional()
  @IsString()
  branch?: string = 'main';

  @IsOptional()
  @IsString()
  subPath?: string = '';

  @IsOptional()
  @IsString()
  sshKeyId?: string;
}
