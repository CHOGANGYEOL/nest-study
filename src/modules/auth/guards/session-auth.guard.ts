import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';

@Injectable()
export class SessionAuthGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    const cookieName = this.config.get<string>('AUTH_SESSION_ID_NAME') ?? 'sid';
    const cookies = (req as Request & { cookies?: unknown }).cookies;
    if (typeof cookies !== 'object' || cookies === null) {
      throw new UnauthorizedException();
    }
    const value = (cookies as Record<string, unknown>)[cookieName];
    if (typeof value !== 'string') {
      throw new UnauthorizedException();
    }
    (req as Request & { sessionId: string }).sessionId = value;
    return true;
  }
}
