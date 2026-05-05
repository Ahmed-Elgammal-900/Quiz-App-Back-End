import {
  Controller,
  Delete,
  Get,
  NotFoundException,
  Res,
} from '@nestjs/common';
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
import { clearTokenCookies } from '../../utils/clear-cookie';

@ApiTags('User')
@ApiCookieAuth('access_token')
@Controller('user')
export class UserController {
  constructor(
    private configService: ConfigService,
    private readonly userService: UserService,
  ) {}

  /**
   * Retrieve the authenticated user's profile information.
   * @param id - The unique identifier of the current user, extracted from the request.
   * @returns An object containing the user's id, name, email and providers.
   * @throws {NotFoundException} If the user does not exist in the database.
   */
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiResponse({
    status: 200,
    description: 'User profile retrieved successfully.',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'string', example: 'uuid-here' },
        name: { type: 'string', example: 'example' },
        email: { type: 'string', example: 'example@email.com' },
        providers: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['local', 'google'],
          },
          example: ['local'],
        },
      },
    },
  })
  @ApiResponse({ status: 404, description: 'User not found.' })
  @Get()
  async getUser(@CurrentUser('id') id: string) {
    const user = await this.userService.findOne({ id });

    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }

    return {
      id: user.id,
      name: user.name,
      email: user.email,
      providers: user.providers,
    };
  }

  /**
   * Delete a user from database and remove cookies
   * @route DELETE /user
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

    clearTokenCookies(res, this.configService);

    return message;
  }
}
