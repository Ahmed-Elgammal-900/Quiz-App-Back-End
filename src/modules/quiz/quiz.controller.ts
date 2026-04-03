import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  Param,
  ParseUUIDPipe,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiCookieAuth,
  ApiParam,
  ApiQuery,
  ApiOkResponse,
  ApiUnauthorizedResponse,
  ApiBody,
} from '@nestjs/swagger';
import { QuizService } from './quiz.service';
import { CurrentUser } from '../../common/decorators/user.decorator';
import { PaginationDto } from './dto/pagination.dto';
import { InsertProgressDto } from './dto/insert-progress.dto';
import { PauseQuizDto } from './dto/pause-quiz.dto';
import { QuizProgressStatus } from './constants/quiz-progress-status';

@ApiTags('Quizzes')
@ApiCookieAuth('access_token')
@Controller('quizzes')
export class QuizController {
  constructor(private readonly quizService: QuizService) {}

  /**
   * Retrieves all quizzes with their progress status for a specific user.
   * @route GET /quizzes
   */
  @Get()
  @ApiOperation({
    summary: 'Get all quizzes',
    description:
      'Retrieves all quizzes with their progress status for the authenticated user.',
  })
  @ApiResponse({
    status: 200,
    description: 'List of quizzes with progress status',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getQuizzes(@CurrentUser('id') userId: string) {
    return this.quizService.getQuizzes(userId);
  }

  /**
   * Retrieves all active quiz activities for the authenticated user.
   *
   * Returns quizzes that are currently in progress or paused,
   * sorted by the most recent attempt first.
   *
   * @param user - The authenticated user extracted from the JWT token
   * @returns A list of active quiz progress records with quiz title
   */
  @Get('activities')
  @ApiOperation({
    summary: 'Get user quiz activities',
    description:
      'Returns all quizzes that are currently in progress or paused for the authenticated user, sorted by most recent attempt.',
  })
  @ApiOkResponse({
    description: 'Active quiz activities retrieved successfully',
    schema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          status: {
            type: 'string',
            enum: [QuizProgressStatus.IN_PROGRESS, QuizProgressStatus.PAUSED],
          },
          score: { type: 'number', nullable: true },
          passed: { type: 'boolean' },
          remainingTimeSeconds: { type: 'number', nullable: true },
          attemptAt: { type: 'string', format: 'date-time', nullable: true },
          quiz: {
            type: 'object',
            properties: {
              title: { type: 'string' },
            },
          },
        },
      },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Invalid or missing JWT token' })
  getActivities(@CurrentUser('id') id: string) {
    return this.quizService.getActivities(id);
  }

  /**
   * Retrieves statistics for a specific user including
   * total quizzes, passed quizzes, average score, and total score.
   * @route GET /quizzes/stats
   */
  @Get('stats')
  @ApiOperation({
    summary: 'Get user statistics',
    description:
      'Retrieves statistics for the authenticated user including total quizzes, passed quizzes, average score, and total score.',
  })
  @ApiResponse({
    status: 200,
    description: 'User statistics',
    schema: {
      example: {
        totalQuizzes: 10,
        passedQuizzes: 7,
        averageScore: 85.5,
        totalScore: 598,
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getUserStats(@CurrentUser('id') userId: string) {
    return this.quizService.getUserStats(userId);
  }

  /**
   * Retrieves the leaderboard of users ordered by
   * passed quizzes count and average score.
   * @route GET /quizzes/leaderboard
   */
  @Get('leaderboard')
  @ApiOperation({
    summary: 'Get leaderboard',
    description:
      'Retrieves the leaderboard of users ordered by passed quizzes count and average score.',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    description: 'Page number',
    example: 1,
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    description: 'Number of items per page',
    example: 10,
  })
  @ApiResponse({ status: 200, description: 'Paginated leaderboard' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getLeaderboard(@Query() { page, limit }: PaginationDto) {
    return this.quizService.getLeaderboard(page, limit);
  }

  /**
   * Retrieves the names and IDs of all quizzes a user has passed.
   * @route GET /quizzes/passed
   */

  @Get('passed')
  @ApiOperation({
    summary: 'Get passed quizzes',
    description:
      'Retrieves the names and IDs of all quizzes the authenticated user has passed.',
  })
  @ApiResponse({
    status: 200,
    description: 'List of passed quiz names and IDs',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getPassedQuizzesNames(@CurrentUser('id') userId: string) {
    return this.quizService.getPassedQuizzesNames(userId);
  }

  /**
   * Retrieves all answers for a specific question.
   * @route GET /quizzes/questions/:questionId/answers
   */
  @Get('questions/:questionId/answers')
  @ApiOperation({
    summary: 'Get answers for a question',
    description: 'Retrieves all answers for a specific question.',
  })
  @ApiParam({
    name: 'questionId',
    description: 'UUID of the question',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @ApiResponse({ status: 200, description: 'List of answers for the question' })
  @ApiResponse({ status: 400, description: 'Invalid UUID' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getAnswersByQuestion(@Param('questionId', ParseUUIDPipe) questionId: string) {
    return this.quizService.getAnswersByQuestion(questionId);
  }

  /**
   * Retrieves a user's answer for a specific question.
   * @route GET /quizzes/questions/:questionId/answered
   */
  @Get('questions/:questionId/answered')
  @ApiOperation({
    summary: "Get user's answer for a question",
    description:
      "Retrieves the authenticated user's selected answer for a specific question.",
  })
  @ApiParam({
    name: 'questionId',
    description: 'UUID of the question',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @ApiResponse({ status: 200, description: "User's answer for the question" })
  @ApiResponse({ status: 400, description: 'Invalid UUID' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getUserQuizAnswer(
    @CurrentUser('id') userId: string,
    @Param('questionId', ParseUUIDPipe) questionId: string,
  ) {
    return this.quizService.getUserQuizAnswer(userId, questionId);
  }

  /**
   * Retrieves paginated questions for a specific quiz including their answers.
   * @route GET /quizzes/:quizId/questions
   */
  @Get(':quizId/questions')
  @ApiOperation({
    summary: 'Get paginated questions for a quiz',
    description:
      'Retrieves paginated questions for a specific quiz including their answers.',
  })
  @ApiParam({
    name: 'quizId',
    description: 'UUID of the quiz',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    description: 'Page number',
    example: 1,
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    description: 'Number of items per page',
    example: 10,
  })
  @ApiResponse({
    status: 200,
    description: 'Paginated list of questions with answers',
  })
  @ApiResponse({ status: 400, description: 'Invalid UUID' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getQuestionsByQuiz(
    @Param('quizId', ParseUUIDPipe) quizId: string,
    @Query() { page, limit }: PaginationDto,
  ) {
    return this.quizService.getQuestionsByQuiz(quizId, page, limit);
  }

  /**
   * Retrieves a user's progress for a specific quiz.
   * @route GET /quizzes/:quizId/progress
   */
  @Get(':quizId/progress')
  @ApiOperation({
    summary: "Get user's quiz progress",
    description:
      "Retrieves the authenticated user's progress for a specific quiz.",
  })
  @ApiParam({
    name: 'quizId',
    description: 'UUID of the quiz',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @ApiResponse({ status: 200, description: 'Quiz progress for the user' })
  @ApiResponse({ status: 400, description: 'Invalid UUID' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getQuizProgress(
    @CurrentUser('id') userId: string,
    @Param('quizId', ParseUUIDPipe) quizId: string,
  ) {
    return this.quizService.getQuizProgress(userId, quizId);
  }

  /**
   * Starts or restarts a quiz session for a user.
   * - If user already passed, only updates attemptAt without resetting progress
   * - If user has not passed, resets all progress fields and records attempt time
   * @route POST /quizzes/:quizId/start
   */
  @Post(':quizId/start')
  @ApiOperation({
    summary: 'Start or restart a quiz',
    description:
      'Starts a new quiz session. If the user already passed, only updates attemptAt. Otherwise resets all progress and records attempt time.',
  })
  @ApiParam({
    name: 'quizId',
    description: 'UUID of the quiz',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @ApiResponse({
    status: 201,
    description: 'Quiz started successfully',
    schema: { example: { message: 'Quiz started successfully' } },
  })
  @ApiResponse({ status: 400, description: 'Invalid UUID' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async startQuiz(
    @CurrentUser('id') userId: string,
    @Param('quizId', ParseUUIDPipe) quizId: string,
  ) {
    await this.quizService.startQuiz(userId, quizId);
    return { message: 'Quiz started successfully' };
  }

  /**
   * Saves a user's answer for a question and updates their quiz progress.
   * Calculates score, marks quiz as completed if last question,
   * and deletes answers if user passed.
   * @route POST /quizzes/:quizId/progress
   */
  @Post(':quizId/progress')
  @ApiOperation({
    summary: 'Save answer and update progress',
    description:
      "Saves the user's answer for a question, updates score, marks quiz as completed if last question, and deletes answers if user passed.",
  })
  @ApiParam({
    name: 'quizId',
    description: 'UUID of the quiz',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @ApiBody({ type: InsertProgressDto })
  @ApiResponse({ status: 201, description: 'Progress updated successfully' })
  @ApiResponse({ status: 400, description: 'Invalid UUID or body' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  insertUserProgress(
    @CurrentUser('id') userId: string,
    @Param('quizId', ParseUUIDPipe) quizId: string,
    @Body() body: InsertProgressDto,
  ) {
    return this.quizService.insertUserProgress(
      userId,
      quizId,
      body.questionId,
      body.selectedAnswerId,
    );
  }

  /**
   * Pauses a quiz session saving the current question and remaining time.
   * @route POST /quizzes/:quizId/pause
   */
  @Post(':quizId/pause')
  @ApiOperation({
    summary: 'Pause a quiz session',
    description:
      'Pauses the quiz session saving the current question and remaining time.',
  })
  @ApiParam({
    name: 'quizId',
    description: 'UUID of the quiz',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @ApiBody({ type: PauseQuizDto })
  @ApiResponse({
    status: 201,
    description: 'Quiz paused successfully',
    schema: { example: { message: 'Quiz paused successfully' } },
  })
  @ApiResponse({ status: 400, description: 'Invalid UUID or body' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async pauseQuiz(
    @CurrentUser('id') userId: string,
    @Param('quizId', ParseUUIDPipe) quizId: string,
    @Body() body: PauseQuizDto,
  ) {
    await this.quizService.pauseQuiz(
      userId,
      quizId,
      body.pausedAtQuestionId,
      body.remainingTimeSeconds,
    );
    return { message: 'Quiz paused successfully' };
  }
}
