import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiKeyService } from '../api-key.service';

@Injectable()
export class ApiKeyAuthGuard implements CanActivate {
  constructor(private readonly apiKeyService: ApiKeyService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const apiKeyHeader = request.headers['x-api-key'] || request.query['apiKey'];

    if (!apiKeyHeader) {
      throw new UnauthorizedException('API Key is missing');
    }

    const apiKey = await this.apiKeyService.validateKey(apiKeyHeader);
    if (!apiKey) {
      throw new UnauthorizedException('Invalid API Key');
    }

    // Attach user to request for further use if needed
    request.user = apiKey.user;
    return true;
  }
}
