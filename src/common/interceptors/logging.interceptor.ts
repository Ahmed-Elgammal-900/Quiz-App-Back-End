import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler) {
    const request = context.switchToHttp().getRequest();

    const { method, url, user } = request;
    const safeUrl = typeof url === 'string' ? url.split('?')[0] : url;
    const actor = user?.id ? 'authenticated' : 'guest';
    const start = Date.now();

    this.logger.log(`→ ${method} ${safeUrl} — actor: ${actor}`);

    return next.handle().pipe(
      tap({
        next: () => {
          const duration = Date.now() - start;
          this.logger.log(`← ${method} ${safeUrl} — ${duration}ms`);
        },
        error: (error) => {
          const duration = Date.now() - start;
          this.logger.warn(
            `← ${method} ${safeUrl} — failed in ${duration}ms: ${error?.message ?? 'unknown error'}`,
          );
        },
      }),
    );
  }
}
