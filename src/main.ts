import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import { ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';

/**
 * Bootstraps the NestJS application.
 * Configures middleware, security, CORS, validation, and starts the HTTP server.
 *
 * @throws {Error} If FRONT_END_ORIGIN environment variable is not set
 */
async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['verbose', 'debug', 'log', 'warn', 'error', 'fatal'],
  });

  const frontEndOrigin = process.env.FRONT_END_ORIGIN;
  if (!frontEndOrigin) {
    throw new Error('FRONT_END_ORIGIN is required');
  }

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

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
