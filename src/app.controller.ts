import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiOkResponse } from '@nestjs/swagger';

@Controller('health')
export class AppController {
  constructor(private readonly appService: AppService) {}

  @ApiOkResponse({
    description: 'Health check',
    schema: {
      example: { ok: true, uptime: 123.45 },
    },
  })
  @Get('health')
  getHealth() {
    return this.appService.health();
  }
}
