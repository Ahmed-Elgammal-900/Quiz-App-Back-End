import { Controller, Delete, Res } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiCookieAuth,
} from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { UserService } from './user.service';
import { Response } from 'express';
import { CurrentUser } from '../../common/decorators/user.decorator';
import { UserResponse } from '../auth/types/response-types';

@ApiTags('User')
@ApiCookieAuth('access_token')
@Controller('user')
export class UserController {
  constructor(
    private configService: ConfigService,
    private readonly userService: UserService,
  ) {}

  /**
   * Delete a user from database and remove cookies
   * @route DELETE /User
   * @param user - user response from jwt guards
   * @param res - server response
   * @returns message confirming successful deletion
   */
  @Delete()
  @ApiOperation({
    summary: 'Delete user account',
    description:
      'Deletes the authenticated user from the database and clears both token cookies.',
  })
  @ApiResponse({
    status: 200,
    description: 'User deleted successfully',
    schema: { example: { message: 'User deleted successfully' } },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
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
