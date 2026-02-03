import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { LoginDto } from './dto/login.dto';
import { PrismaService } from 'src/database/prisma/prisma.service';
import { ConfigService } from '@nestjs/config';

export type JwtPayload = {
  sub: string; // user id
  email: string;
};

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  // 예시용 해시(실무는 bcrypt/argon2 권장)
  private hash(value: string): string {
    return crypto.createHash('sha256').update(value).digest('hex');
  }

  private async signAccess(payload: JwtPayload): Promise<string> {
    const secret =
      this.config.get<string>('AUTH_ACCESS_SECRET') ?? 'dev-access';
    const expiresIn =
      this.config.get<JwtSignOptions['expiresIn']>('AUTH_ACCESS_EXPIRES_IN') ??
      '15m';

    return this.jwt.signAsync(payload, { secret, expiresIn });
  }

  private sessionExpiresInMs(): number {
    const fallbackMs = 14 * 24 * 60 * 60 * 1000;
    const expiresIn =
      this.config.get<JwtSignOptions['expiresIn']>('AUTH_SESSION_EXPIRES_IN') ??
      '14d';

    if (typeof expiresIn === 'number' && Number.isFinite(expiresIn)) {
      return Math.max(0, expiresIn) * 1000;
    }

    if (typeof expiresIn === 'string') {
      const match = /^(\d+)\s*([smhd])$/i.exec(expiresIn);
      if (match) {
        const value = Number(match[1]);
        const unit = match[2].toLowerCase();
        const unitMs =
          unit === 's'
            ? 1000
            : unit === 'm'
              ? 60 * 1000
              : unit === 'h'
                ? 60 * 60 * 1000
                : 24 * 60 * 60 * 1000;
        return value * unitMs;
      }
    }

    return fallbackMs;
  }

  getSessionExpiresInMs(): number {
    return this.sessionExpiresInMs();
  }

  private sessionExpiresAt(): Date {
    return new Date(Date.now() + this.sessionExpiresInMs());
  }

  async issueTokens(
    user: { id: string; email: string },
    meta?: { userAgent?: string; ip?: string },
  ) {
    const session = await this.prisma.session.create({
      data: {
        userId: user.id,
        expiresAt: this.sessionExpiresAt(),
        userAgent: meta?.userAgent ?? null,
        ip: meta?.ip ?? null,
      },
    });

    const accessToken = await this.signAccess({
      sub: user.id,
      email: user.email,
    });

    return { accessToken, sessionId: session.id };
  }

  async rotateSessionId(
    sessionId: string,
    meta?: { userAgent?: string; ip?: string },
  ) {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
      include: { user: true },
    });
    if (!session) throw new UnauthorizedException('Invalid session');
    if (session.revokedAt) throw new UnauthorizedException('Session revoked');
    if (session.expiresAt.getTime() < Date.now())
      throw new UnauthorizedException('Session expired');

    if (
      (session.userAgent &&
        meta?.userAgent &&
        session.userAgent !== meta.userAgent) ||
      (session.ip && meta?.ip && session.ip !== meta.ip)
    ) {
      await this.prisma.session.update({
        where: { id: session.id },
        data: { revokedAt: new Date() },
      });
      throw new UnauthorizedException('Session mismatch');
    }

    const newSession = await this.prisma.session.create({
      data: {
        userId: session.userId,
        expiresAt: this.sessionExpiresAt(),
        userAgent: meta?.userAgent ?? null,
        ip: meta?.ip ?? null,
      },
    });

    await this.prisma.session.update({
      where: { id: session.id },
      data: { revokedAt: new Date() },
    });

    const newAccess = await this.signAccess({
      sub: session.user.id,
      email: session.user.email,
    });

    return { accessToken: newAccess, sessionId: newSession.id };
  }

  async revokeSession(sessionId: string) {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
    });
    if (!session) throw new UnauthorizedException('Invalid session');
    await this.prisma.session.update({
      where: { id: sessionId },
      data: { revokedAt: new Date() },
    });
  }

  async validateUser(email: string, password: string) {
    const user = await this.usersService.findByEmailForAuth(email);
    if (!user) return null;

    const passwordHash = this.hash(password);
    if (user.passwordHash !== passwordHash) return null;

    return { id: user.id, email: user.email };
  }

  async login(user: { id: string; email: string }) {
    const payload: JwtPayload = { sub: user.id, email: user.email };
    return {
      accessToken: await this.jwt.signAsync(payload),
    };
  }

  async loginWithDto(dto: LoginDto) {
    const user = await this.validateUser(dto.email, dto.password);
    if (!user) throw new UnauthorizedException('Invalid credentials');
    return this.login(user);
  }

  async register(dto: { email: string; password: string }) {
    const exists = await this.usersService.findByEmail(dto.email);
    if (exists) throw new ConflictException('Email already exists');

    const passwordHash = this.hash(dto.password);

    const user = await this.usersService.create(
      {
        email: dto.email,
        password: dto.password,
      },
      passwordHash,
    );

    return this.login({
      id: user.id,
      email: user.email,
    });
  }
}
