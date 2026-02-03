import { ApiProperty } from '@nestjs/swagger';

export class UserResponseDto {
  @ApiProperty({ example: 'b3c9f7e1-4d3a-4c1a-9c2a-8a2c5b9f1f23' })
  id!: string;

  @ApiProperty({ example: 'test@example.com' })
  email!: string;

  @ApiProperty({ example: '2026-02-02T12:34:56.000Z' })
  createdAt!: string; // Date를 그대로 써도 되지만 Swagger 예시는 string(date-time)이 보통 깔끔
}
