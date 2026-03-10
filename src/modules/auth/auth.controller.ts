import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Req,
  Res,
  Patch,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/signup.dto';
import { AuthGuard } from '@nestjs/passport';
import { Response } from 'express';
import { LoginDto } from './dto/login.dto';
import { UpdateAuthDto } from './dto/forget-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UserResponse } from './types/respnse-types';
import { Public } from 'src/common/decorators/public.decorator';
import { ConfigService } from '@nestjs/config';
import { CurrentUser } from 'src/common/decorators/user.decorator';
import { VerifyOtpDto } from './dto/otp.dto';
import { UpdatePasswordDto } from './dto/change-password.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private configService: ConfigService,
  ) {}

  @Public()
  @Post('signup')
  async create(
    @Body() createAuthDto: CreateAuthDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.createUser(createAuthDto);
    const { accessToken, refreshToken } =
      await this.authService.generateTokens(user);
    this.setTokenCookies(res, accessToken, refreshToken);
    return { message: 'signup success', isEmalVerified: user.isEmailVerified };
  }

  @Public()
  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.validateLocalUser(loginDto);
    const { accessToken, refreshToken } =
      await this.authService.generateTokens(user);
    this.setTokenCookies(res, accessToken, refreshToken);
    return { message: 'login success', isEmalVerified: user.isEmailVerified };
  }

  @Public()
  @UseGuards(AuthGuard('google'))
  @Get('google')
  googleLogin() {}

  @Public()
  @UseGuards(AuthGuard('google'))
  @Get('google/callback')
  async googleCallback(
    @CurrentUser() user: UserResponse,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, refreshToken } =
      await this.authService.generateTokens(user);
    this.setTokenCookies(res, accessToken, refreshToken);
    res.redirect(`${this.configService.get('ORIGIN')}/dashboard`);
  }

  @Public()
  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('refresh-token')
  async refresh(
    @CurrentUser() user: UserResponse,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken } = await this.authService.updateAccessToken(
      user.id,
      user.email,
    );

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000,
    });

    return { message: 'success access token' };
  }

  @Patch('change-password')
  async changePaswword(
    @CurrentUser() user: UserResponse,
    @Body() updatePasswordDto: UpdatePasswordDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.changePassword(user.id, updatePasswordDto);

    return { massege: 'password changed successfully' };
  }

  @Public()
  @Post('forget-password')
  async forgetPassword(
    @Body() updateAuthDto: UpdateAuthDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const message = await this.authService.forgotPassword(updateAuthDto.email);

    return message;
  }

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
    const { accessToken, refreshToken } =
      await this.authService.generateTokens(user);
    this.setTokenCookies(res, accessToken, refreshToken);
    return { message: 'Password reset successful' };
  }

  @Post('verify-email')
  verifyEmail(@CurrentUser() user: UserResponse, @Body() dto: VerifyOtpDto) {
    return this.authService.verifyOtp(user.id, dto.otp);
  }

  @Post('resend-otp')
  resendOtp(@CurrentUser() user: UserResponse) {
    return this.authService.resendOtp(user.id);
  }

  @Post('logout')
  async logout(
    @CurrentUser() user: UserResponse,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.logout(user.id);
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    return { message: 'logout success' };
  }

  private setTokenCookies(
    res: Response,
    accessToken: string,
    refreshToken: string,
  ) {
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
  }
}
