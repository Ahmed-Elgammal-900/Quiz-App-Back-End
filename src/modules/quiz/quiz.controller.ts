import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  Param,
  ParseUUIDPipe,
} from '@nestjs/common';
import { QuizService } from './quiz.service';
import { CurrentUser } from '../../common/decorators/user.decorator';
import { PaginationDto } from './dto/pagination.dto';
import { InsertProgressDto } from './dto/insert-progress.dto';
import { PauseQuizDto } from './dto/pause-quiz.dto';

@Controller('quizzes')
export class QuizController {
  constructor(private readonly quizService: QuizService) {}

  /**
   * Retrieves all quizzes with their progress status for a specific user.
   * @route GET /quizzes
   */
  @Get()
  getQuizzes(@CurrentUser('id') userId: string) {
    return this.quizService.getQuizzes(userId);
  }

  /**
   * Retrieves paginated questions for a specific quiz including their answers.
   * @route GET /quizzes/:quizId/questions
   */
  @Get(':quizId/questions')
  getQuestionsByQuiz(
    @Param('quizId', ParseUUIDPipe) quizId: string,
    @Query() { page, limit }: PaginationDto,
  ) {
    return this.quizService.getQuestionsByQuiz(quizId, page, limit);
  }

  /**
   * Retrieves all answers for a specific question.
   * @route GET /quizzes/questions/:questionId/answers
   */
  @Get('questions/:questionId/answers')
  getAnswersByQuestion(@Param('questionId', ParseUUIDPipe) questionId: string) {
    return this.quizService.getAnswersByQuestion(questionId);
  }

  /**
   * Retrieves the names and IDs of all quizzes a user has passed.
   * @route GET /quizzes/passed
   */
  @Get('passed')
  getPassedQuizzesNames(@CurrentUser('id') userId: string) {
    return this.quizService.getPassedQuizzesNames(userId);
  }

  /**
   * Retrieves a user's answer for a specific question.
   * @route GET /quizzes/questions/:questionId/answered
   */
  @Get('questions/:questionId/answered')
  getUserQuizAnswer(
    @CurrentUser('id') userId: string,
    @Param('questionId', ParseUUIDPipe) questionId: string,
  ) {
    return this.quizService.getUserQuizAnswer(userId, questionId);
  }

  /**
   * Retrieves a user's progress for a specific quiz.
   * @route GET /quizzes/:quizId/progress
   */
  @Get(':quizId/progress')
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

  /**
   * Retrieves statistics for a specific user including
   * total quizzes, passed quizzes, average score, and total score.
   * @route GET /quizzes/stats
   */
  @Get('stats')
  getUserStats(@CurrentUser('id') userId: string) {
    return this.quizService.getUserStats(userId);
  }

  /**
   * Retrieves the leaderboard of users ordered by
   * passed quizzes count and average score.
   * @route GET /quizzes/leaderboard
   */
  @Get('leaderboard')
  getLeaderboard(@Query() { page, limit }: PaginationDto) {
    return this.quizService.getLeaderboard(page, limit);
  }
}
