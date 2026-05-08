import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  Param,
  ParseUUIDPipe,
  ParseIntPipe,
  Delete,
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
  ApiNoContentResponse,
} from '@nestjs/swagger';
import { QuizService } from './quiz.service';
import { CurrentUser } from '../../common/decorators/user.decorator';
import { PaginationDto } from './dto/pagination.dto';
import { InsertProgressDto } from './dto/insert-progress.dto';
import { PauseQuizDto } from './dto/pause-quiz.dto';
import { QuizProgressStatus } from './constants/quiz-progress-status';
import { SkipThrottle } from '@nestjs/throttler';

@ApiTags('Quizzes')
@ApiCookieAuth('access_token')
@Controller('quizzes')
export class QuizController {
  constructor(private readonly quizService: QuizService) {}

  /** Returns all quizzes with their progress status for the authenticated user. */
  @Get()
  @ApiOperation({
    summary: 'Get all quizzes',
    description:
      'Retrieves all quizzes with their progress status for the authenticated user.',
  })
  @ApiOkResponse({ description: 'List of quizzes with progress status' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  getQuizzes(@CurrentUser('id') userId: string) {
    return this.quizService.getQuizzes(userId);
  }

  /** Returns quizzes currently in progress or paused, sorted by most recent attempt. */
  @Get('activities')
  @ApiOperation({
    summary: 'Get user quiz activities',
    description:
      'Returns all quizzes that are currently in progress or paused, sorted by most recent attempt.',
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
            properties: { title: { type: 'string' } },
          },
        },
      },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Invalid or missing JWT token' })
  getActivities(@CurrentUser('id') id: string) {
    return this.quizService.getActivities(id);
  }

  /** Returns the authenticated user's final result for a completed quiz. */
  @Get(':quizId/get-result')
  @ApiOperation({
    summary: 'Get quiz result',
    description:
      "Retrieves the authenticated user's result for a specific quiz.",
  })
  @ApiParam({
    name: 'quizId',
    description: 'UUID of the quiz',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @ApiOkResponse({ description: 'Quiz result for the user' })
  @ApiResponse({ status: 400, description: 'Invalid UUID' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  getResult(
    @CurrentUser('id') userId: string,
    @Param('quizId', ParseUUIDPipe) quizId: string,
  ) {
    return this.quizService.getResult(userId, quizId);
  }

  /** Returns aggregate stats for the authenticated user: total quizzes, passed, average score, and total score. */
  @Get('stats')
  @ApiOperation({
    summary: 'Get user statistics',
    description:
      'Retrieves total quizzes, passed quizzes, average score, and total score for the authenticated user.',
  })
  @ApiOkResponse({
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
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  getUserStats(@CurrentUser('id') userId: string) {
    return this.quizService.getUserStats(userId);
  }

  /** Returns the top 3 users on the leaderboard ranked by passed quizzes, total score, and average score. */
  @Get('top-three')
  @ApiOperation({
    summary: 'Get top 3 leaderboard users',
    description:
      'Returns top 3 users ranked by passed quizzes, total score, and average score.',
  })
  @ApiOkResponse({
    description: 'Top 3 users retrieved successfully',
    schema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          userId: { type: 'string', example: 'uuid' },
          name: { type: 'string', example: 'Ahmed' },
          totalScore: { type: 'number', example: 950 },
        },
      },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  getTopThree() {
    return this.quizService.getTopThree();
  }

  /** Returns the authenticated user's current leaderboard rank and stats. */
  @Get('my-rank')
  @ApiOperation({
    summary: 'Get current user rank',
    description:
      "Returns the authenticated user's rank and stats on the leaderboard.",
  })
  @ApiOkResponse({
    description: 'User rank retrieved successfully',
    schema: {
      type: 'object',
      properties: {
        rank: { type: 'number', example: 42 },
        name: { type: 'string', example: 'Ahmed' },
        totalScore: { type: 'number', example: 450 },
      },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  getUserRank(@CurrentUser('id') userId: string) {
    return this.quizService.getUserRank(userId);
  }

  /** Deletes all submitted answers for the authenticated user on a specific quiz. */
  @Delete(':quizId/delete-user-answers')
  @ApiOperation({
    summary: 'Delete user answers for a quiz',
    description:
      "Deletes all of the authenticated user's submitted answers for a specific quiz.",
  })
  @ApiParam({
    name: 'quizId',
    description: 'UUID of the quiz',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @ApiNoContentResponse({ description: 'Answers deleted successfully' })
  @ApiResponse({ status: 400, description: 'Invalid UUID' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  deleteUserAnswers(
    @CurrentUser('id') userId: string,
    @Param('quizId', ParseUUIDPipe) quizId: string,
  ) {
    return this.quizService.deleteUserAnswers(userId, quizId);
  }

  /** Returns a paginated leaderboard ordered by passed quizzes, total score, and average score. */
  @Get('leaderboard')
  @ApiOperation({
    summary: 'Get leaderboard',
    description:
      'Retrieves paginated leaderboard ordered by passed quizzes count, total score, and average score.',
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
  @ApiOkResponse({ description: 'Paginated leaderboard' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  getLeaderboard(@Query() { page, limit }: PaginationDto) {
    return this.quizService.getLeaderboard(page, limit);
  }

  /** Returns the names and IDs of all quizzes the authenticated user has passed. */
  @Get('earned-badges')
  @ApiOperation({
    summary: 'Get earned badges',
    description:
      'Retrieves the names and IDs of all quizzes the authenticated user has passed.',
  })
  @ApiOkResponse({ description: 'List of earned badges' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  getPassedQuizzesBadges(@CurrentUser('id') userId: string) {
    return this.quizService.getPassedQuizzesBadges(userId);
  }

  /** Returns paginated questions with their answers for a specific quiz. */
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
  @ApiOkResponse({ description: 'Paginated list of questions with answers' })
  @ApiResponse({ status: 400, description: 'Invalid UUID' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  getQuestionsByQuiz(
    @Param('quizId', ParseUUIDPipe) quizId: string,
    @Query() { page, limit }: PaginationDto,
  ) {
    return this.quizService.getQuizWithQuestions(quizId, page, limit);
  }

  /** Returns only the IDs of all questions belonging to a specific quiz. */
  @Get(':quizId/questions/ids')
  @ApiOperation({
    summary: 'Get question IDs for a quiz',
    description:
      'Retrieves only the IDs of all questions belonging to a specific quiz.',
  })
  @ApiParam({
    name: 'quizId',
    description: 'UUID of the quiz',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @ApiOkResponse({ description: 'List of question UUIDs' })
  @ApiResponse({ status: 400, description: 'Invalid UUID' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  getQuestionsIds(@Param('quizId', ParseUUIDPipe) quizId: string) {
    return this.quizService.getQuestionsIds(quizId);
  }

  /** Returns the authenticated user's progress records for a specific quiz. */
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
  @ApiQuery({
    name: 'limit',
    required: false,
    description: 'Max number of progress records to return',
  })
  @ApiOkResponse({ description: 'Quiz progress for the user' })
  @ApiResponse({ status: 400, description: 'Invalid UUID' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  getQuizProgress(
    @CurrentUser('id') userId: string,
    @Param('quizId', ParseUUIDPipe) quizId: string,
    @Query('limit', new ParseIntPipe({ optional: true })) limit?: number,
  ) {
    return this.quizService.getQuizUserProgress(userId, quizId, limit);
  }

  /**
   * If the user already passed this quiz, only `attemptAt` is updated —
   * score and answers are preserved. Otherwise all progress is reset
   * and a fresh attempt is recorded.
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
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  async startQuiz(
    @CurrentUser('id') userId: string,
    @Param('quizId', ParseUUIDPipe) quizId: string,
  ) {
    await this.quizService.startQuiz(userId, quizId);
    return { message: 'Quiz started successfully' };
  }

  /**
   * Saves the user's answer for a question and updates their quiz progress.
   * Marks the quiz as completed if this is the last question.
   * Clears all stored answers if the user passed.
   */
  @SkipThrottle()
  @Post(':quizId/progress')
  @ApiOperation({
    summary: 'Save answer and update progress',
    description:
      "Saves the user's answer for a question, updates score, marks quiz as completed if last question, and clears answers if the user passed.",
  })
  @ApiParam({
    name: 'quizId',
    description: 'UUID of the quiz',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @ApiBody({ type: InsertProgressDto })
  @ApiResponse({ status: 201, description: 'Progress updated successfully' })
  @ApiResponse({ status: 400, description: 'Invalid UUID or body' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
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

  /** Pauses the quiz session, saving the current question index and remaining time. */
  @Post(':quizId/pause')
  @ApiOperation({
    summary: 'Pause a quiz session',
    description:
      'Pauses the quiz session, saving the current question index and remaining time.',
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
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  async pauseQuiz(
    @CurrentUser('id') userId: string,
    @Param('quizId', ParseUUIDPipe) quizId: string,
    @Body() body: PauseQuizDto,
  ) {
    await this.quizService.pauseQuiz(
      userId,
      quizId,
      body.pausedAtQuestionIndex,
      body.remainingTimeSeconds,
    );
    return { message: 'Quiz paused successfully' };
  }
}
