import { Controller, Get } from '@nestjs/common';
import { Public } from './common/decorators/public.decorator';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

/**
 * Root application controller.
 * Handles the entry point route for the API.
 */
@ApiTags('Health')
@Controller()
export class AppController {
  /**
   * Returns a welcome message for the API.
   * Publicly accessible — no authentication required.
   *
   * @route GET /
   * @access Public
   * @returns A welcome string confirming the API is running
   */
  @Public()
  @Get()
  @ApiOperation({
    summary: 'Health check',
    description: 'Returns a welcome message confirming the API is running',
  })
  @ApiResponse({ status: 200, description: 'API is running', type: String })
  getHello(): string {
    return 'Welcome to Quizzer API';
  }
}
