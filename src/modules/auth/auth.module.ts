import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtRefreshStrategy } from './strategies/jwtRefersh.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/googleAuth.strategy';
import { MailModule } from '../../modules/mail/mail.module';
import { UserModule } from '../user/user.module';

@Module({
  imports: [PassportModule, JwtModule.register({}), MailModule, UserModule],
  controllers: [AuthController],
  providers: [AuthService, JwtRefreshStrategy, JwtStrategy, GoogleStrategy],
})
export class AuthModule {}
