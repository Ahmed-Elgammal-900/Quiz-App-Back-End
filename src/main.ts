import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import { ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

/**
 * Bootstraps the NestJS application.
 * Configures middleware, security, CORS, validation, and starts the HTTP server.
 *
 * @throws {Error} If FRONT_END_ORIGIN environment variable is not set
 * @throws {TypeError} If FRONT_END_ORIGIN is not a valid URL or uses a disallowed protocol
 */
async function bootstrap() {
  // env var check
  const frontEndOriginRaw = process.env.FRONT_END_ORIGIN;
  if (!frontEndOriginRaw) {
    throw new Error('FRONT_END_ORIGIN is required');
  }
  let frontEndOrigin: string;
  try {
    const parsed = new URL(frontEndOriginRaw);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error();
    }
    frontEndOrigin = parsed.origin;
  } catch {
    throw new Error('FRONT_END_ORIGIN must be a valid absolute http(s) URL');
  }

  // app init
  const app = await NestFactory.create(AppModule, {
    logger: ['verbose', 'debug', 'log', 'warn', 'error', 'fatal'],
  });
  app.use(helmet());

  app.enableCors({ origin: frontEndOrigin, credentials: true });

  app.useGlobalFilters(new GlobalExceptionFilter());

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      forbidNonWhitelisted: true,
      whitelist: true,
    }),
  );

  app.use(cookieParser());
  // Swagger Config
  const config = new DocumentBuilder()
    .setTitle('Quizzer API')
    .setDescription('The Quizzer API documentation')
    .setVersion('1.0')
    .addCookieAuth('access_token')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);
  //
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
