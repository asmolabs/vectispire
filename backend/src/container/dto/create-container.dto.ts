import { IsString, IsOptional, IsNumber } from 'class-validator';

export class CreateContainerDto {
  @IsString()
  @IsOptional()
  registry?: string;

  @IsString()
  imageName: string;

  @IsString()
  @IsOptional()
  tag?: string;

  @IsNumber()
  @IsOptional()
  scanIntervalMinutes?: number;

  @IsString()
  @IsOptional()
  scanCron?: string;
}
