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

  let parsed: URL;
  try {
    parsed = new URL(frontEndOriginRaw);
  } catch {
    throw new Error('FRONT_END_ORIGIN must be a valid absolute http(s) URL');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('FRONT_END_ORIGIN must use http or https protocol');
  }
  const frontEndOrigin = parsed.origin;

  const isProduction = process.env.NODE_ENV === 'production';
  // app init
  const app = await NestFactory.create(AppModule, {
    logger: isProduction
      ? ['log', 'warn', 'error', 'fatal']
      : ['verbose', 'debug', 'log', 'warn', 'error', 'fatal'],
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

  if (process.env.NODE_ENV !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('Quizzer API')
      .setDescription('The Quizzer API documentation')
      .setVersion('1.0')
      .addCookieAuth('access_token')
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('docs', app, document);
  }

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
