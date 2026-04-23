import { IsString, IsOptional, IsEnum, IsNumber } from 'class-validator';

export class CreateVexDecisionDto {
  @IsString()
  vulnerabilityId: string;

  @IsString()
  packageName: string;

  @IsOptional()
  @IsString()
  purl?: string;

  @IsString()
  @IsEnum(['not_affected', 'affected', 'fixed', 'under_investigation'])
  status: string;

  @IsOptional()
  @IsString()
  justification?: string;

  @IsOptional()
  @IsString()
  response?: string;

  @IsOptional()
  @IsString()
  comment?: string;

  @IsNumber()
  repositoryId: number;
}
