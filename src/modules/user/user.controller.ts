import { Controller } from '@nestjs/common';
import { Get, Delete, Res } from '@nestjs/common';
import { UserService } from './user.service';
import { Response } from 'express';
import { CurrentUser } from 'src/common/decorators/user.decorator';
import { UserResponse } from '../auth/types/respnse-types';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}
  @Delete('delete')
  async remove(
    @CurrentUser() user: UserResponse,
    @Res({ passthrough: true }) res: Response,
  ) {
    const message = await this.userService.deleteUser(user);

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    return message;
  }
}
