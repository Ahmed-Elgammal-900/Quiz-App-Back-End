import { Response } from 'express';
import { ConfigService } from '@nestjs/config';

/**
 * Clear authentication cookies from the response
 * @param res - Express response object
 * @param configService - NestJS config service to determine environment
 */
export function clearTokenCookies(res: Response, configService: ConfigService) {
  const cookieOptions = {
    httpOnly: true,
    secure: configService.get('NODE_ENV') === 'production',
    sameSite: 'lax' as const,
    path: '/',
  };

  res.clearCookie('access_token', cookieOptions);
  res.clearCookie('refresh_token', cookieOptions);
}
