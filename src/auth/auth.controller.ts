import {
  Controller,
  Get,
  Post,
  Body,
  Delete,
  UseGuards,
  Req,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { AuthGuard } from '@nestjs/passport';
import { Request, Response } from 'express';
import { LoginDto } from './dto/login.dto';
import { User } from './entities/user.entity';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

interface GoogleAuthRequest extends Request {
  user: User;
}

interface JwtRequest extends Request {
  user: User;
}

interface JwtRefreshRequest extends Request {
  user: { userId: string; email: string };
}
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async create(
    @Body() createAuthDto: CreateAuthDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.createUser(createAuthDto);
    const { accessToken, refreshToken } = this.authService.generateTokens(user);
    this.setTokenCookies(res, accessToken, refreshToken);
    return { message: 'signup success' };
  }

  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.validateLocalUser(loginDto);
    const { accessToken, refreshToken } = this.authService.generateTokens(user);
    this.setTokenCookies(res, accessToken, refreshToken);
    return { message: 'login success' };
  }

  @UseGuards(AuthGuard('google'))
  @Get('google')
  googleLogin() {}

  @UseGuards(AuthGuard('google'))
  @Get('google/callback')
  googleCallback(
    @Req() req: GoogleAuthRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, refreshToken } = this.authService.generateTokens(
      req.user,
    );
    this.setTokenCookies(res, accessToken, refreshToken);
    return { message: 'google auth success' };
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('refresh')
  async refresh(
    @Req() req: JwtRefreshRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken } = await this.authService.updateAccessToken(req.user);

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000,
    });

    return { message: 'success access token' };
  }

  @Post('forget-password')
  async forgetPassword(
    @Body() updateAuthDto: UpdateAuthDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const message = await this.authService.requestPasswordReset(
      updateAuthDto.email,
    );

    return message;
  }

  @Post('reset-password')
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.resetPassword(
      resetPasswordDto.password,
      resetPasswordDto.resetToken,
    );
    const { accessToken, refreshToken } = this.authService.generateTokens(user);
    this.setTokenCookies(res, accessToken, refreshToken);
    return { message: 'Password reset successful' };
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('logout')
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    return { message: 'logout success' };
  }

  @UseGuards(AuthGuard('jwt'))
  @Delete('delete')
  async remove(
    @Req() req: JwtRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const message = await this.authService.deleteUser(req.user);

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    return message;
  }

  private setTokenCookies(
    res: Response,
    accessToken: string,
    refreshToken: string,
  ) {
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
  }
}
