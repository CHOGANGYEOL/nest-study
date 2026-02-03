import { Body, Controller, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';
import { RegisterUserDto } from './dto/register.dto';
import type { Request, Response } from 'express';
import { SessionAuthGuard } from './guards/session-auth.guard';
import { ConfigService } from '@nestjs/config';

type LoginRequest = Request & { user: { id: string; email: string } };
type RefreshRequest = Request & { sessionId: string };

@Controller('auth')
export class AuthController {
  private readonly sessionIdCookieName: string;

  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
  ) {
    this.sessionIdCookieName =
      this.config.get<string>('AUTH_SESSION_ID_NAME') ?? 'sid';
  }

  private setSessionIdCookie(res: Response, sessionId: string) {
    res.cookie(this.sessionIdCookieName, sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/auth',
      maxAge: this.authService.getSessionExpiresInMs(),
    });
  }

  private clearSessionId(res: Response) {
    res.clearCookie(this.sessionIdCookieName, { path: '/auth' });
  }

  @ApiOperation({ summary: 'Login' })
  @ApiBody({ type: LoginDto })
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(
    @Req() req: LoginRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const meta = {
      userAgent: req.headers['user-agent'],
      ip: req.ip,
    };
    const { accessToken, sessionId } = await this.authService.issueTokens(
      req.user,
      meta,
    );
    this.setSessionIdCookie(res, sessionId);
    return { accessToken };
  }

  @UseGuards(SessionAuthGuard)
  @Post('refresh')
  async refresh(
    @Req() req: RefreshRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const meta = {
      userAgent: req.headers['user-agent'],
      ip: req.ip,
    };
    const rotated = await this.authService.rotateSessionId(req.sessionId, meta);
    this.setSessionIdCookie(res, rotated.sessionId);
    return { accessToken: rotated.accessToken };
  }

  @UseGuards(SessionAuthGuard)
  @Post('logout')
  async logout(
    @Req() req: RefreshRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.revokeSession(req.sessionId);
    this.clearSessionId(res);
    return { ok: true };
  }

  @Post('register')
  register(@Body() dto: RegisterUserDto) {
    return this.authService.register(dto);
  }
}
