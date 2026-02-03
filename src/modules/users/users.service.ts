import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma/prisma.service';
import { RegisterUserDto } from '../auth/dto/register.dto';
import { User } from '@prisma/client';

type UserPublic = Pick<User, 'id' | 'email' | 'createdAt' | 'updatedAt'>;
type UserAuth = Pick<User, 'id' | 'email' | 'passwordHash'>;

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  async findByEmail(email: User['email']): Promise<UserPublic | null> {
    return this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  }

  async findById(id: User['id']): Promise<UserPublic> {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  /**
   * Auth 전용 조회: passwordHash 포함 (로그인 검증/비번 변경 등)
   */
  async findByEmailForAuth(email: User['email']): Promise<UserAuth | null> {
    return this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        passwordHash: true,
      },
    });
  }

  async create(
    dto: RegisterUserDto,
    passwordHash: User['passwordHash'],
  ): Promise<UserPublic> {
    const exists = await this.findByEmail(dto.email);
    if (exists) throw new ConflictException('Email already exists');

    return this.prisma.user.create({
      data: {
        email: dto.email,
        passwordHash,
      },
      select: {
        id: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  }
}
