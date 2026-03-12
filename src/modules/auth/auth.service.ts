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
  /**
   * Registers a new user and sends an OTP verification email.
   *
   * @param createAuthDto - The registration data (name, email, password)
   * @returns The newly created user object
   */
  async createUser(createAuthDto: CreateAuthDto) {
    const user = await this.userService.createUser(createAuthDto);
    this.sendOtp(user.id, user.email);
    return user;
  }

  /**
   * Validates a Google OAuth user. Creates the user if they don't exist.
   * Throws if the account was previously deleted.
   * Sends an OTP if the email is not yet verified.
   *
   * @param googleDto - Google OAuth profile data (email, name, googleId)
   * @returns Basic user info (id, email, isEmailVerified)
   * @throws {ConflictException} If the account was previously deleted
   */
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

    return {
      id: user.id,
      email: user.email,
      isEmailVerified: user.isEmailVerified,
    };
  }

  /**
   * Validates a local (email/password) login.
   * Sends OTP if the user's email is not yet verified.
   *
   * @param loginDto - Login credentials (email, password)
   * @returns The authenticated user object
   * @throws {BadRequestException} If the account was deleted or password is incorrect
   * @throws {NotFoundException} If no user exists with the given email
   */
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

  /**
   * Resets a user's password using a valid reset token.
   * Clears the reset token from the database after use.
   *
   * @param newPassword - The new plain-text password to set
   * @param token - The raw reset token sent to the user's email
   * @returns The updated user object
   * @throws {BadRequestException} If the token is invalid or has expired
   */
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

  /**
   * Changes the password for an authenticated user.
   * Validates the current password and ensures the new one is different.
   *
   * @param id - The ID of the user changing their password
   * @param updatePasswordDto - Contains currentPassword and newPassword
   * @throws {NotFoundException} If the user is not found
   * @throws {BadRequestException} If current password is wrong or new password matches the old one
   */
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

  /**
   * Generates a cryptographically random 6-digit OTP.
   *
   * @returns A 6-digit OTP string
   */
  private generateOtp(): string {
    return crypto.randomInt(100000, 999999).toString();
  }

  /**
   * Verifies an OTP for email verification.
   * Tracks failed attempts and blocks after 5 incorrect tries.
   *
   * @param userId - The ID of the user verifying their email
   * @param otp - The plain-text OTP submitted by the user
   * @returns The verified user object
   * @throws {BadRequestException} If OTP is missing, expired, invalid, or max attempts exceeded
   */
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
    return this.userService.findOne({ id: userId });
  }

  /**
   * Resends the OTP to a user who hasn't verified their email yet.
   *
   * @param userId - The ID of the user requesting a new OTP
   * @returns A success message object
   * @throws {BadRequestException} If the email is already verified
   */
  async resendOtp(userId: string) {
    const user = await this.userService.findOne({ id: userId });

    if (user.isEmailVerified) {
      throw new BadRequestException('Email already verified');
    }

    return this.sendOtp(userId, user.email);
  }

  /**
   * Generates and sends an OTP email to the user.
   * Enforces a 60-second cooldown between sends.
   * Hashes the OTP before storing it.
   *
   * @param userId - The ID of the user to send the OTP to
   * @param email - The email address to deliver the OTP to
   * @returns A success message object
   * @throws {BadRequestException} If called again within the 60-second cooldown window
   */
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

  /**
   * Initiates the forgot password flow by sending a reset link to the user's email.
   * Always returns the same message to prevent email enumeration.
   *
   * @param email - The email address to send the reset link to
   * @returns A generic success message (same whether email exists or not)
   */
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

  /**
   * Logs out the user by revoking their refresh token from the database.
   *
   * @param id - The ID of the user logging out
   * @throws {UnauthorizedException} If the user is not found
   */
  async logout(id: string) {
    const user = await this.userService.findOne({ id });
    if (!user) throw new UnauthorizedException();

    await this.userService.clearToken(TokenType.REFRESH, id);
  }

  /**
   * Generates a new access token and refresh token pair for a user.
   * Hashes and stores the refresh token in the database.
   *
   * @param user - The user to generate tokens for (must include id, email, isEmailVerified)
   * @returns An object containing the signed accessToken and refreshToken
   */
  async generateTokens(user: UserResponse) {
    const payload = {
      sub: user.id,
      email: user.email,
      isEmailVerified: user.isEmailVerified,
    };

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

  /**
   * Rotates the refresh token — invalidates the old one and issues a new token pair.
   * Used by the refresh endpoint to maintain token rotation security.
   *
   * @param userId - The ID of the user requesting a token refresh
   * @param oldRefreshToken - The current refresh token to invalidate
   * @returns A new accessToken and refreshToken pair
   * @throws {UnauthorizedException} If the user is not found
   */
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
