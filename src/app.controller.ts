import { Controller, Get } from '@nestjs/common';
import { Public } from './common/decorators/public.decorator';

/**
 * Root application controller.
 * Handles the entry point route for the API.
 */
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
  getHello(): string {
    return 'Welcome to Quizzer API';
  }
}
