import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { ApiBearerAuth, ApiOkResponse } from '@nestjs/swagger';
import { UserResponseDto } from './dto/user-response.dto';
import { JwtPayload } from '../auth/auth.service';

type JwtRequest = Request & { user: JwtPayload };

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @ApiOkResponse({ type: UserResponseDto })
  @ApiBearerAuth('access-token')
  @UseGuards(JwtAuthGuard)
  @Get('me')
  async getUser(@Req() req: JwtRequest) {
    const userId = req.user.sub;
    const user = await this.usersService.findById(userId);

    return { id: user.id, email: user.email, createdAt: user.createdAt };
  }
}
