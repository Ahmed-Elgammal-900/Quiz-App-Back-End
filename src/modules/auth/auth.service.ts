import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateAuthDto } from './dto/signup.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { GoogleDto } from './dto/google-auth.dto';
import { LoginDto } from './dto/login.dto';
import * as crypto from 'crypto';
import { MailService } from 'src/modules/mail/mail.service';
import { UserService } from '../user/user.service';
import { UpdatePasswordDto } from './dto/change-password.dto';
import { HASH_SALT_ROUNDS } from './constants/auth.constants';
import { TokenType } from './constants/token-type.constant';
import { UnauthorizedException } from '@nestjs/common';
import { UserResponse } from './types/respnse-types';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailService: MailService,
    private userService: UserService,
  ) {}
  async createUser(createAuthDto: CreateAuthDto) {
    const user = await this.userService.createUser(createAuthDto);
    this.sendOtp(user.id, user.email);
    return user;
  }

  async validateGoogleUser(googleDto: GoogleDto) {
    const { email } = googleDto;
    const deletedUser = await this.userService.findDeletedByEmail(email);
    if (deletedUser) {
      throw new ConflictException('this account was deleted');
    }

    const user = await this.userService.findOrCreateGoogleUser(googleDto);

    if (!user.isEmailVerified) {
      this.sendOtp(user.id, user.email);
    }

    return { id: user.id, email: user.email };
  }

  async validateLocalUser(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const deletedUser = await this.userService.findDeletedByEmail(email);
    if (deletedUser) {
      throw new BadRequestException('this account was deleted');
    }

    const user = await this.userService.findOne({ email });

    if (!user) {
      throw new NotFoundException('User Not Found');
    }

    const truePassword = await bcrypt.compare(password, user.password);

    if (!truePassword) {
      throw new BadRequestException('Password Or Email Incorrect');
    }

    if (!user.isEmailVerified) {
      this.sendOtp(user.id, user.email);
    }

    return user;
  }

  async resetPassword(newPassword: string, token: string) {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const resetToken = await this.userService.getToken(
      TokenType.PASSWORD_RESET,
      undefined,
      hashedToken,
    );

    if (!resetToken) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    if (resetToken.expiresAt < new Date()) {
      await this.userService.clearToken(
        TokenType.PASSWORD_RESET,
        resetToken.userId,
      );
      throw new BadRequestException('Reset token has expired');
    }

    const hashedPassword = await bcrypt.hash(newPassword, HASH_SALT_ROUNDS);
    await this.userService.updateUser(resetToken.userId, {
      password: hashedPassword,
    });

    await this.userService.clearToken(
      TokenType.PASSWORD_RESET,
      resetToken.userId,
    );

    const user = await this.userService.findOne({ id: resetToken.userId });

    return user;
  }

  async changePassword(id: string, updatePasswordDto: UpdatePasswordDto) {
    const user = await this.userService.findOne(id);
    if (!user) throw new NotFoundException('User not found');

    const isMatch = await bcrypt.compare(
      updatePasswordDto.currentPassword,
      user.password,
    );
    if (!isMatch)
      throw new BadRequestException('Current password is incorrect');

    const isSame = await bcrypt.compare(
      updatePasswordDto.newPassword,
      user.password,
    );
    if (isSame) throw new BadRequestException('New password must be different');

    await this.userService.updateUser(id, {
      password: updatePasswordDto.newPassword,
    });
  }

  private generateOtp(): string {
    return crypto.randomInt(100000, 999999).toString();
  }

  async verifyOtp(userId: string, otp: string) {
    const otpToken = await this.userService.getToken(
      TokenType.EMAIL_VERIFY,
      userId,
    );

    if (!otpToken) {
      throw new BadRequestException('No OTP found, please request a new one');
    }

    if (otpToken.attempts >= 5) {
      throw new BadRequestException(
        'Too many attempts, please request a new OTP',
      );
    }

    if (otpToken.expiresAt < new Date()) {
      throw new BadRequestException('OTP expired, please request a new one');
    }

    const isMatch = await bcrypt.compare(otp, otpToken.token);
    if (!isMatch) {
      await this.userService.incrementAttempts(userId);
      throw new BadRequestException('Invalid OTP');
    }

    await this.userService.verifyUser(userId);
    return { message: 'Email verified successfully' };
  }

  async resendOtp(userId: string) {
    const user = await this.userService.findOne({ id: userId });

    if (user.isEmailVerified) {
      throw new BadRequestException('Email already verified');
    }

    return this.sendOtp(userId, user.email);
  }

  async sendOtp(userId: string, email: string) {
    const existing = await this.userService.getToken(
      TokenType.EMAIL_VERIFY,
      userId,
    );

    if (existing?.lastSentAt) {
      const seconds = (Date.now() - existing.lastSentAt.getTime()) / 1000;
      if (seconds < 60) {
        throw new BadRequestException(
          `Wait ${Math.ceil(60 - seconds)}s before resending`,
        );
      }
    }

    const otp = this.generateOtp();
    const hashedOtp = await bcrypt.hash(otp, HASH_SALT_ROUNDS);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await this.userService.saveToken(
      userId,
      hashedOtp,
      TokenType.EMAIL_VERIFY,
      expiresAt,
    );

    await this.mailService.sendOtpEmail(email, otp);

    return { message: 'OTP sent successfully' };
  }

  async forgotPassword(email: string) {
    const user = await this.userService.findOne({ email });
    if (!user) return { message: 'If email exists, reset link has been sent' };

    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await this.userService.saveToken(
      user.id,
      hashedToken,
      TokenType.PASSWORD_RESET,
      expiresAt,
    );
    await this.mailService.sendResetPasswordEmail(email, resetToken);

    return { message: 'If email exists, reset link has been sent' };
  }

  async logout(id: string) {
    const user = await this.userService.findOne({ id });
    if (!user) throw new UnauthorizedException();

    await this.userService.clearToken(TokenType.REFRESH, id);
  }

  async generateTokens(user: UserResponse) {
    const payload = { sub: user.id, email: user.email };

    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_ACCESS_SECRET'),
      expiresIn: '15m',
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_REFRESH_SECRET'),
      expiresIn: '7d',
    });

    const hashedRefresh = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await this.userService.saveToken(
      user.id,
      hashedRefresh,
      TokenType.REFRESH,
      expiresAt,
    );

    return { accessToken, refreshToken };
  }

  async updateAccessToken(userId: string, oldRefreshToken: string) {
    const user = await this.userService.findOne({ id: userId });
    if (!user) throw new UnauthorizedException();

    const hashedOld = crypto
      .createHash('sha256')
      .update(oldRefreshToken)
      .digest('hex');
    await this.userService.clearToken(TokenType.REFRESH, undefined, hashedOld);

    const tokens = await this.generateTokens(user);

    return tokens;
  }
}
