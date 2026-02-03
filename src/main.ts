import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  app.use(cookieParser());

  const config = new DocumentBuilder()
    .setTitle('Swagger')
    .setDescription('The Nest Test API Description')
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
      'access-token', // 이 이름이 아래 @ApiBearerAuth()의 name과 매칭됨
    )
    .build();

  const documentFactory = () => SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('swagger', app, documentFactory);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // DTO에 없는 필드 자동 제거
      forbidNonWhitelisted: true, // DTO에 없는 필드가 들어오면 400 에러
      transform: true, // 타입 변환 query string -> number
    }),
  );

  await app.listen(process.env.PORT ?? 3000);
}
void bootstrap();
