import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from 'src/modules/user/user.service';
import { Request } from 'express';
import { TokenType } from '../constants/token-type.constant';
import * as crypto from 'crypto';
import { UnauthorizedException } from '@nestjs/common';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(
    private configService: ConfigService,
    private userService: UserService,
  ) {
    const secret = configService.get<string>('JWT_REFRESH_SECRET');

    if (!secret) {
      throw new Error('JWT_SECRET is not defined in environment');
    }
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => req?.cookies?.['refresh_token'] ?? null,
      ]),
      ignoreExpiration: false,
      secretOrKey: secret,
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: { sub: string; email: string }) {
    const refreshToken = req.cookies?.['refresh_token'];

    const hashedToken = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    const token = await this.userService.getToken(
      TokenType.REFRESH,
      payload.sub,
      hashedToken,
    );

    if (!token) throw new UnauthorizedException('Invalid refresh token');
    if (token.expiresAt < new Date())
      throw new UnauthorizedException('Refresh token expired');

    return { id: payload.sub, email: payload.email };
  }
}
