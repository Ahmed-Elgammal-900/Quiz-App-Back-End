import { Controller, Delete, Res } from '@nestjs/common';
import { UserService } from './user.service';
import { Response } from 'express';
import { CurrentUser } from '../../common/decorators/user.decorator';
import { UserResponse } from '../auth/types/response-types';
import { ConfigService } from '@nestjs/config';

@Controller('user')
export class UserController {
  constructor(
    private configService: ConfigService,
    private readonly userService: UserService,
  ) {}

  /**
   * Delete a user from database and remove cookies
   * @param user - user response from jwt guards
   * @param res - server response
   * @returns message confirming successful deletion
   */
  @Delete('delete')
  async remove(
    @CurrentUser() user: UserResponse,
    @Res({ passthrough: true }) res: Response,
  ) {
    const message = await this.userService.deleteUser(user);

    this.clearTokenCookies(res);

    return message;
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
