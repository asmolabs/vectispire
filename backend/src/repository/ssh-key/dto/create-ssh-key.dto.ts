import { IsNotEmpty, IsString, IsOptional, IsUUID } from 'class-validator';

export class CreateSSHKeyDto {
  @IsOptional()
  @IsUUID()
  id?: string;

  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  privateKey: string;

  @IsOptional()
  @IsString()
  publicKey?: string;
}
