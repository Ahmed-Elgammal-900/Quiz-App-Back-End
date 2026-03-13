import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Res,
  Patch,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/signup.dto';
import { AuthGuard } from '@nestjs/passport';
import { Response } from 'express';
import { LoginDto } from './dto/login.dto';
import { ForgetPasswordDto } from './dto/forget-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { JwtUserWithRefresh, UserResponse } from './types/response-types';
import { Public } from 'src/common/decorators/public.decorator';
import { ConfigService } from '@nestjs/config';
import { CurrentUser } from '../../common/decorators/user.decorator';
import { VerifyOtpDto } from './dto/otp.dto';
import { UpdatePasswordDto } from './dto/change-password.dto';
import { ResendOtpDto } from './dto/resend-otp.dto';
import {
  ACCESS_TOKEN_MAX_AGE,
  REFRESH_TOKEN_MAX_AGE,
} from './constants/auth.constants';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private configService: ConfigService,
  ) {}

  /**
   * Registers a new user account and sends an OTP verification email.
   * Does not issue tokens — user must verify email first.
   *
   * @route POST /auth/signup
   * @access Public
   * @returns A success message and the new user's ID
   */
  @Public()
  @Post('signup')
  async create(
    @Body() createAuthDto: CreateAuthDto,
    @Res({ passthrough: true }) _res: Response,
  ) {
    const user = await this.authService.createUser(createAuthDto);
    return { message: 'signup success', userId: user.id };
  }

  /**
   * Authenticates a user with email and password.
   * Issues access and refresh token cookies only if the email is verified.
   * If not verified, a new OTP is sent automatically.
   *
   * @route POST /auth/login
   * @access Public
   * @returns A success message and the user's ID
   */
  @Public()
  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.validateLocalUser(loginDto);
    if (user.isEmailVerified) {
      const { accessToken, refreshToken } =
        await this.authService.generateTokens(user);

      this.setTokenCookies(res, accessToken, refreshToken);
    }
    return {
      message: user.isEmailVerified
        ? 'login success'
        : 'otp verification required',
      userId: user.id,
      isEmailVerified: user.isEmailVerified,
    };
  }

  /**
   * Initiates the Google OAuth2 login flow.
   * Redirects the user to Google's consent screen.
   *
   * @route GET /auth/google
   * @access Public
   */
  @Public()
  @UseGuards(AuthGuard('google'))
  @Get('google')
  googleLogin() {}

  /**
   * Handles the Google OAuth2 callback after user consent.
   * Issues token cookies if the user's email is already verified.
   * If not verified, an OTP is sent automatically.
   *
   * @route GET /auth/google/callback
   * @access Public (Google OAuth guard)
   * @returns A success message and the user's ID
   */
  @Public()
  @UseGuards(AuthGuard('google'))
  @Get('google/callback')
  async googleCallback(
    @CurrentUser() user: UserResponse,
    @Res({ passthrough: true }) res: Response,
  ) {
    if (user.isEmailVerified) {
      const { accessToken, refreshToken } =
        await this.authService.generateTokens(user);
      this.setTokenCookies(res, accessToken, refreshToken);
    }

    return {
      message: user.isEmailVerified
        ? 'google auth success'
        : 'otp verification required',
      userId: user.id,
      isEmailVerified: user.isEmailVerified,
    };
  }

  /**
   * Rotates both access and refresh tokens using a valid refresh token cookie.
   * The old refresh token is invalidated and replaced with a new one (token rotation).
   *
   * @route POST /auth/refresh-token
   * @access Public (jwt-refresh guard)
   * @returns A success message
   */
  @Public()
  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('refresh-token')
  async refresh(
    @CurrentUser() user: JwtUserWithRefresh,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, refreshToken } = await this.authService.refreshTokens(
      user.id,
      user.refreshToken,
    );
    this.setTokenCookies(res, accessToken, refreshToken);

    return { message: 'success access token' };
  }

  /**
   * Changes the password for the currently authenticated user.
   * Requires the current password to be correct and the new one to be different.
   *
   * @route PATCH /auth/change-password
   * @access Protected (jwt-access guard)
   * @returns A success message
   */
  @Patch('change-password')
  async changePassword(
    @CurrentUser() user: UserResponse,
    @Body() updatePasswordDto: UpdatePasswordDto,
    @Res({ passthrough: true }) _res: Response,
  ) {
    await this.authService.changePassword(user.id, updatePasswordDto);

    return { message: 'password changed successfully' };
  }

  /**
   * Sends a password reset link to the provided email address.
   * Always returns the same response to prevent email enumeration.
   *
   * @route POST /auth/forget-password
   * @access Public
   * @returns A generic success message
   */
  @Public()
  @Post('forget-password')
  async forgetPassword(
    @Body() updateAuthDto: ForgetPasswordDto,
    @Res({ passthrough: true }) _res: Response,
  ) {
    const message = await this.authService.forgotPassword(updateAuthDto.email);

    return message;
  }

  /**
   * Resets the user's password using a valid reset token from their email.
   * Issues new access and refresh token cookies on success.
   *
   * @route POST /auth/reset-password
   * @access Public
   * @returns A success message
   */
  @Public()
  @Post('reset-password')
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.resetPassword(
      resetPasswordDto.password,
      resetPasswordDto.resetToken,
    );
    if (user.isEmailVerified) {
      const { accessToken, refreshToken } =
        await this.authService.generateTokens(user);
      this.setTokenCookies(res, accessToken, refreshToken);
    }

    return {
      message: user.isEmailVerified
        ? 'Password reset successful'
        : 'Password reset successful, please verify your email',
      isEmailVerified: user.isEmailVerified,
      userId: user.id,
    };
  }

  /**
   * Verifies a user's email using the OTP sent during registration.
   * Issues access and refresh token cookies on successful verification.
   *
   * @route POST /auth/verify-email
   * @access Public
   * @returns A success message
   */
  @Public()
  @Post('verify-email')
  async verifyEmail(
    @Body() dto: VerifyOtpDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.verifyOtp(dto.id, dto.otp);

    const { accessToken, refreshToken } =
      await this.authService.generateTokens(user);
    this.setTokenCookies(res, accessToken, refreshToken);
    return { message: 'email verified' };
  }

  /**
   * Resends the OTP to a user who hasn't verified their email yet.
   * Subject to a 60-second cooldown between requests.
   *
   * @route POST /auth/resend-otp
   * @access Public
   * @returns A success message
   */
  @Public()
  @Post('resend-otp')
  async resendOtp(@Body() dto: ResendOtpDto) {
    return await this.authService.resendOtp(dto.id);
  }

  /**
   * Logs out the authenticated user by revoking their refresh token
   * and clearing both token cookies from the browser.
   *
   * @route POST /auth/logout
   * @access Protected (jwt-access guard)
   * @returns A success message
   */
  @Post('logout')
  async logout(
    @CurrentUser() user: UserResponse,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.logout(user.id);
    this.clearTokenCookies(res);

    return { message: 'logout success' };
  }

  /**
   * Sets HttpOnly access and refresh token cookies on the response.
   * Cookies are marked secure in production and use strict SameSite policy.
   *
   * @param res - The Express response object
   * @param accessToken - The signed JWT access token (expires in 15 minutes)
   * @param refreshToken - The signed JWT refresh token (expires in 7 days)
   */
  private setTokenCookies(
    res: Response,
    accessToken: string,
    refreshToken: string,
  ) {
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: ACCESS_TOKEN_MAX_AGE,
      path: '/',
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: REFRESH_TOKEN_MAX_AGE,
      path: '/',
    });
  }

  /**
   * Clear cookies with options
   * @param res server response
   * @returns void
   */
  private clearTokenCookies(res: Response) {
    const cookieOptions = {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict' as const,
      path: '/',
    };

    res.clearCookie('access_token', cookieOptions);
    res.clearCookie('refresh_token', cookieOptions);
  }
}
