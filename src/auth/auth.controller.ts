import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
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

interface AuthRequest extends Request {
  user: User;
}

interface JwtRequest extends Request {
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

  @UseGuards(AuthGuard('local'))
  @Post('login')
  login(
    @Body() loginDto: LoginDto,
    @Req() req: AuthRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, refreshToken } = this.authService.generateTokens(
      req.user,
    );
    this.setTokenCookies(res, accessToken, refreshToken);
    return { message: 'login success' };
  }

  @UseGuards(AuthGuard('google'))
  @Get('google')
  googleLogin() {}

  @UseGuards(AuthGuard('google'))
  @Get('google/callback')
  googleCallback(@Req() req: AuthRequest, @Res() res: Response) {
    const { accessToken, refreshToken } = this.authService.generateTokens(
      req.user,
    );
    this.setTokenCookies(res, accessToken, refreshToken);
    return { message: 'google auth success' };
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('refresh')
  async refresh(@Req() req: JwtRequest, @Res() res: Response) {
    const { accessToken } = await this.authService.updateAccessToken(
      req.user.userId,
    );

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000,
    });

    return { message: 'success access token' };
  }

  @Patch('updatePassword')
  updatePassword(@Req() req: Request, @Res() res: Response) {}

  @UseGuards(AuthGuard('jwt'))
  @Post('logout')
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    return { message: 'logout success' };
  }

  @UseGuards(AuthGuard('jwt'))
  @Delete('delete')
  async remove(@Req() req: JwtRequest, @Res() res: Response) {
    const message = await this.authService.deleteUser(
      req.user.userId,
      req.user.email,
    );

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
