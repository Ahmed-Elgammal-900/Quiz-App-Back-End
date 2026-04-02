import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Res,
  Patch,
  Query,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiCookieAuth,
  ApiBody,
  ApiQuery,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/signup.dto';
import { AuthGuard } from '@nestjs/passport';
import { Response } from 'express';
import { LoginDto } from './dto/login.dto';
import { ForgetPasswordDto } from './dto/forget-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { JwtUserWithRefresh, UserResponse } from './types/response-types';
import { Public } from '../../common/decorators/public.decorator';
import { ConfigService } from '@nestjs/config';
import { CurrentUser } from '../../common/decorators/user.decorator';
import { VerifyOtpDto } from './dto/otp.dto';
import { UpdatePasswordDto } from './dto/change-password.dto';
import { ResendOtpDto } from './dto/resend-otp.dto';
import {
  ACCESS_TOKEN_MAX_AGE,
  REFRESH_TOKEN_MAX_AGE,
} from './constants/auth.constants';
import { ExchangeQueryDto } from './dto/exchange-query.dto';

@ApiTags('Auth')
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
  @ApiOperation({
    summary: 'Register a new user',
    description:
      'Creates a new account and sends an OTP verification email. Tokens are not issued until email is verified.',
  })
  @ApiBody({ type: CreateAuthDto })
  @ApiResponse({
    status: 201,
    description: 'User registered successfully',
    schema: { example: { message: 'signup success', userId: 'uuid' } },
  })
  @ApiResponse({ status: 409, description: 'Email already exists' })
  @ApiResponse({ status: 400, description: 'Validation error' })
  async create(@Body() createAuthDto: CreateAuthDto) {
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
  @ApiOperation({
    summary: 'Login with email & password',
    description:
      'Authenticates the user. Issues HttpOnly token cookies only if email is verified. Otherwise sends a new OTP.',
  })
  @ApiBody({ type: LoginDto })
  @ApiResponse({
    status: 200,
    description: 'Login successful or OTP required',
    schema: {
      example: {
        message: 'login success',
        userId: 'uuid',
        isEmailVerified: true,
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
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
  @ApiOperation({
    summary: 'Initiate Google OAuth2 login',
    description: 'Redirects the user to Google consent screen.',
  })
  @ApiResponse({ status: 302, description: 'Redirects to Google OAuth' })
  googleLogin() {}

  /**
   * Handles the Google OAuth2 callback after user consent.
   * Generates a short-lived OAuth code and redirects the client
   * to the frontend callback URL with the code and userId as query params.
   *
   * @route GET /auth/google/callback
   * @access Public (Google OAuth guard)
   */
  @Public()
  @UseGuards(AuthGuard('google'))
  @Get('google/callback')
  @ApiOperation({
    summary: 'Google OAuth2 callback',
    description:
      'Handles redirect from Google. Generates a short-lived OAuth code and redirects to the frontend callback URL.',
  })
  @ApiResponse({
    status: 302,
    description: 'Redirects to frontend callback with OAuth code.',
  })
  async googleCallback(
    @CurrentUser() user: UserResponse,
    @Res() res: Response,
  ) {
    const OAuthCode = await this.authService.generateOAuthCode(user.id);
    const frontEndOrigin = this.configService.get('FRONT_END_ORIGIN');
    return res.redirect(`${frontEndOrigin}/api/callback?code=${OAuthCode}`);
  }

  /**
   * Exchanges an OAuth authorization code for authenticated session tokens.
   *
   * This endpoint is the OAuth 2.0 callback handler. After a user authorizes
   * the application with a third-party provider, the provider redirects here
   * with a temporary `code` and the `userId` that initiated the flow.
   * The code is consumed (single-use), tokens are generated, and set as
   * HTTP-only cookies on the response.
   *
   * @route GET /auth/exchange
   * @param code - The short-lived OAuth authorization code from the provider.
   * @param userId - The UUID of the user who initiated the OAuth flow.
   * @param res - The Express response object used to set auth cookies.
   * @returns JSON `{ success: true }` on successful exchange.
   * @throws {UnauthorizedException} If the code is invalid, expired, or already used.
   * @throws {BadRequestException} If `userId` is not a valid UUID.
   */
  @ApiOperation({
    summary: 'Exchange OAuth code for session tokens',
    description:
      'Consumes a one-time OAuth authorization code and issues access/refresh token cookies. ' +
      'This endpoint is called by the OAuth provider redirect after user authorization.',
  })
  @ApiQuery({
    name: 'code',
    required: true,
    type: String,
    description:
      'The short-lived OAuth authorization code returned by the provider.',
    example: '4/0AX4XfWh...',
  })
  @ApiQuery({
    name: 'userId',
    required: true,
    type: String,
    format: 'uuid',
    description: 'UUID of the user who initiated the OAuth flow.',
    example: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  })
  @ApiResponse({
    status: 200,
    description:
      'OAuth code successfully exchanged. Auth cookies are set on the response.',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description:
      'Invalid request — `userId` is not a valid UUID or `code` is missing.',
  })
  @ApiResponse({
    status: 401,
    description:
      'Unauthorized — OAuth code is invalid, expired, or has already been used.',
  })
  @Public()
  @Get('exchange')
  async exchange(
    @Query() { code }: ExchangeQueryDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.consumeOAuthCode(code);

    const { accessToken, refreshToken } =
      await this.authService.generateTokens(user);

    this.setTokenCookies(res, accessToken, refreshToken);
    return { success: true };
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
  @ApiOperation({
    summary: 'Rotate access & refresh tokens',
    description:
      'Uses the refresh_token cookie to issue new token pair. Old refresh token is invalidated.',
  })
  @ApiCookieAuth('refresh_token')
  @ApiResponse({
    status: 200,
    description: 'Tokens rotated successfully',
    schema: { example: { message: 'success access token' } },
  })
  @ApiResponse({ status: 401, description: 'Invalid or expired refresh token' })
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
  @ApiCookieAuth('access_token')
  @ApiOperation({
    summary: 'Change password',
    description:
      'Updates password for the authenticated user. Requires current password to be correct.',
  })
  @ApiBody({ type: UpdatePasswordDto })
  @ApiResponse({
    status: 200,
    description: 'Password changed successfully',
    schema: { example: { message: 'password changed successfully' } },
  })
  @ApiResponse({
    status: 400,
    description: 'Current password is incorrect or new password is the same',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async changePassword(
    @CurrentUser() user: UserResponse,
    @Body() updatePasswordDto: UpdatePasswordDto,
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
  @ApiOperation({
    summary: 'Request password reset',
    description:
      'Sends a reset link to the provided email. Always returns the same response to prevent email enumeration.',
  })
  @ApiBody({ type: ForgetPasswordDto })
  @ApiResponse({
    status: 200,
    description: 'Reset email sent (if account exists)',
    schema: {
      example: { message: 'If this email exists, a reset link has been sent' },
    },
  })
  async forgetPassword(@Body() updateAuthDto: ForgetPasswordDto) {
    return await this.authService.forgotPassword(updateAuthDto.email);
  }

  /**
   * Resets a user's password using a valid reset token from email.
   * Issues token cookies if the email is already verified.
   * If not verified, returns userId so the client can redirect to OTP verification.
   *
   * @route POST /auth/reset-password
   * @access Public
   * @returns A success message, isEmailVerified flag, and userId
   */
  @Public()
  @Post('reset-password')
  @ApiOperation({
    summary: 'Reset password with token',
    description:
      'Resets password using the token from the reset email. Issues token cookies on success.',
  })
  @ApiBody({ type: ResetPasswordDto })
  @ApiResponse({
    status: 200,
    description: 'Password reset successful',
    schema: {
      example: {
        message: 'Password reset successful',
        isEmailVerified: true,
        userId: 'uuid',
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Invalid or expired reset token' })
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
  @ApiOperation({
    summary: 'Verify email with OTP',
    description:
      'Verifies the user email using the OTP sent during signup. Issues token cookies on success.',
  })
  @ApiBody({ type: VerifyOtpDto })
  @ApiResponse({
    status: 200,
    description: 'Email verified and tokens issued',
    schema: { example: { message: 'email verified' } },
  })
  @ApiResponse({ status: 400, description: 'Invalid or expired OTP' })
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
  @ApiOperation({
    summary: 'Resend OTP',
    description:
      'Resends the verification OTP. Subject to a 60-second cooldown.',
  })
  @ApiBody({ type: ResendOtpDto })
  @ApiResponse({ status: 200, description: 'OTP resent successfully' })
  @ApiResponse({
    status: 400,
    description: 'Cooldown active or email already verified.',
  })
  async resendOtp(@Body() dto: ResendOtpDto) {
    return await this.authService.resendOtp(dto.id);
  }

  /**
   * Verifies the validity of the access token.
   *
   * The global JWT guard intercepts this request and validates
   * the access token automatically. If the token is invalid or
   * expired, the guard returns 401 before reaching this handler.
   *
   * @route POST /auth/verify-access-token
   * @returns `{ success: true }` if the token is valid
   */
  @ApiOperation({ summary: 'Verify access token' })
  @ApiCookieAuth('access_token')
  @ApiResponse({
    status: 200,
    description: 'Token is valid',
    schema: { example: { success: true } },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized — token is missing, invalid, or expired.',
  })
  @Post('verify-access-token')
  async verifyAccessToken() {
    return { success: true };
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
  @ApiOperation({
    summary: 'Logout',
    description: 'Revokes the refresh token and clears both token cookies.',
  })
  @ApiCookieAuth('access_token')
  @ApiResponse({
    status: 200,
    description: 'Logged out successfully',
    schema: { example: { message: 'logout success' } },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
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
      sameSite: 'lax',
      maxAge: ACCESS_TOKEN_MAX_AGE,
      path: '/',
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'lax',
      maxAge: REFRESH_TOKEN_MAX_AGE,
      path: '/',
    });
  }

  /**
   * Clears access and refresh token cookies from the browser.
   *
   * @param res - The Express response object
   */
  private clearTokenCookies(res: Response) {
    const cookieOptions = {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'lax' as const,
      path: '/',
    };

    res.clearCookie('access_token', cookieOptions);
    res.clearCookie('refresh_token', cookieOptions);
  }
}
