import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { DeletedUser } from './entities/deletedUser.entity';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtRefreshStrategy } from './jwtRefersh.strategy';
import { JwtStrategy } from './jwt.strategy';
import { GoogleStrategy } from './googleAuth.strategy';
import { LocalStrategy } from './localAuth.strategy';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, DeletedUser]),
    PassportModule,
    JwtModule.register({}),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtRefreshStrategy, JwtStrategy, GoogleStrategy, LocalStrategy],
})
export class AuthModule {}
