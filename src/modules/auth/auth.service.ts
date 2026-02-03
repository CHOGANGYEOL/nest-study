import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { LoginDto } from './dto/login.dto';

export type JwtPayload = {
  sub: string; // user id
  email: string;
};

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwt: JwtService,
  ) {}

  // 예시용 해시(실무는 bcrypt/argon2 권장)
  private hashPassword(password: string): string {
    return crypto.createHash('sha256').update(password).digest('hex');
  }

  async validateUser(email: string, password: string) {
    const user = await this.usersService.findByEmailForAuth(email);
    if (!user) return null;

    const passwordHash = this.hashPassword(password);
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

    const passwordHash = this.hashPassword(dto.password);

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
