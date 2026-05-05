import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Quiz } from './entities/quiz.entity';
import { Repository } from 'typeorm';
import { Question } from './entities/question.entity';
import { UserQuizProgress } from './entities/user-progress.entity';
import { Answer } from './entities/answer.entity';
import { QuizProgressStatus } from './constants/quiz-progress-status';
import { UserQuizAnswer } from './entities/user-quiz-answer.entity';
import { User } from '../user/entities/user.entity';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import type { LeaderboardEntry, UserRank } from './types/quiz.types';

@Injectable()
export class QuizService {
  constructor(
    @InjectRepository(Quiz)
    private readonly quizRepo: Repository<Quiz>,
    @InjectRepository(Question)
    private readonly questionRepo: Repository<Question>,
    @InjectRepository(Answer)
    private readonly answerRepo: Repository<Answer>,
    @InjectRepository(UserQuizProgress)
    private readonly userQuizProgressRepo: Repository<UserQuizProgress>,
    @InjectRepository(UserQuizAnswer)
    private readonly userQuizAnswerRepo: Repository<UserQuizAnswer>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
  ) {}

  /**
   * Retrieves all quizzes with their progress status for the authenticated user.
   * Merges quiz info with user progress, falling back to null for fields with no progress yet.
   * @param userId - The UUID of the user
   * @returns List of quizzes with score, status, passed, progress, and effective timeInSeconds
   */
  async getQuizzes(userId: string) {
    const info = await this.quizRepo
      .createQueryBuilder('quiz')
      .select([
        'quiz.id',
        'quiz.title',
        'quiz.description',
        'quiz.timeInSeconds',
      ])
      .loadRelationCountAndMap('quiz.questionsCount', 'quiz.questions')
      .getMany();

    const progress = await this.userQuizProgressRepo.find({
      where: { userId },
      select: [
        'quizId',
        'score',
        'progress',
        'status',
        'passed',
        'remainingTimeSeconds',
      ],
    });

    const quizzes = info.map((quiz) => {
      const { timeInSeconds, ...quizWithoutTime } = quiz;
      const quizProgress = progress.find((p) => p.quizId === quiz.id) ?? null;
      return {
        ...quizWithoutTime,
        timeInSeconds: quizProgress?.remainingTimeSeconds || timeInSeconds,
        score: quizProgress?.score ?? null,
        status: quizProgress?.status ?? null,
        passed: quizProgress?.passed ?? null,
        progress: quizProgress?.progress ?? null,
      };
    });

    return quizzes;
  }

  /**
   * Retrieves paginated questions with their answers for a specific quiz.
   * Strips isCorrect and orderIndex from answers before returning.
   * @param quizId - The UUID of the quiz
   * @param page - Page number (default: 1)
   * @param limit - Number of questions per page (default: 10)
   * @returns Quiz title, sanitized questions with answers, and pagination metadata
   */
  async getQuizWithQuestions(
    quizId: string,
    page: number = 1,
    limit: number = 10,
  ) {
    const quiz = await this.quizRepo.findOne({
      select: { title: true },
      where: { id: quizId },
    });

    if (!quiz) {
      throw new NotFoundException('quiz not found');
    }

    const targetPage = page;
    const skip = (targetPage - 1) * limit;

    const questionIds = await this.questionRepo
      .createQueryBuilder('question')
      .select('question.id')
      .where('question.quizId = :quizId', { quizId })
      .orderBy('question.orderIndex', 'ASC')
      .skip(skip)
      .take(limit)
      .getMany();

    const ids = questionIds.map((q) => q.id);

    const total = await this.questionRepo
      .createQueryBuilder('question')
      .where('question.quizId = :quizId', { quizId })
      .getCount();

    const questions =
      ids.length === 0
        ? []
        : await this.questionRepo
            .createQueryBuilder('question')
            .leftJoinAndSelect('question.answers', 'answer')
            .where('question.id IN (:...ids)', { ids })
            .orderBy('question.orderIndex', 'ASC')
            .addOrderBy('answer.orderIndex', 'ASC')
            .getMany();

    const safeQuestions = questions.map(({ answers, orderIndex, ...q }) => {
      return {
        ...q,
        answers: answers.map(({ isCorrect, orderIndex, ...a }) => a),
      };
    });

    return {
      quizTitle: quiz.title,
      questions: safeQuestions,
      pagination: {
        total,
        page,
        limit,
        hasNext: page < Math.ceil(total / limit),
      },
    };
  }

  /**
   * Retrieves the final result of a completed quiz attempt for a user.
   * @param userId - The UUID of the user
   * @param quizId - The UUID of the quiz
   * @returns Quiz title, score, status, passed flag, correct answers count, total questions, and time taken
   * @throws NotFoundException if progress or quiz is not found
   */
  async getResult(userId: string, quizId: string) {
    const progress = await this.userQuizProgressRepo.findOne({
      where: { userId, quizId },
    });
    if (!progress) throw new NotFoundException('progress not found');
    const correctAnswers = await this.userQuizAnswerRepo.count({
      where: { userId, quizId, isCorrect: true },
    });
    const totalQuestions = await this.questionRepo.count({ where: { quizId } });
    const quiz = await this.quizRepo.findOne({
      where: { id: quizId },
      select: { title: true, timeInSeconds: true },
    });
    if (!quiz) throw new NotFoundException('quiz not found');
    return {
      quizTitle: quiz.title,
      score: progress.score,
      status: progress.status,
      passed: progress.passed,
      correctAnswers,
      totalQuestions,
      timeTaken:
        progress.remainingTimeSeconds === 0
          ? quiz.timeInSeconds
          : quiz.timeInSeconds - progress.remainingTimeSeconds,
    };
  }

  /**
   * Retrieves only the ordered IDs of all questions belonging to a quiz.
   * @param quizId - The UUID of the quiz
   * @returns Array of question UUIDs sorted by orderIndex ascending
   */
  async getQuestionsIds(quizId: string) {
    const questions = await this.questionRepo
      .createQueryBuilder('question')
      .select('question.id')
      .where('question.quizId = :quizId', { quizId })
      .orderBy('question.orderIndex', 'ASC')
      .getMany();
    return questions.map((q) => q.id);
  }

  /**
   * Retrieves the authenticated user's progress state for a specific quiz.
   * Calculates which page and question index the user should resume from,
   * based on their answered questions and paused position.
   * @param userId - The UUID of the user
   * @param quizId - The UUID of the quiz
   * @param limit - Number of questions per page used to compute currentPage (default: 10)
   * @returns pausedAt index, array of submitted answers with questionIndex, and currentPage
   */
  async getQuizUserProgress(
    userId: string,
    quizId: string,
    limit: number = 10,
  ) {
    const [progress, userAnswers, totalQuestions] = await Promise.all([
      this.userQuizProgressRepo
        .createQueryBuilder('p')
        .where('p.userId = :userId', { userId })
        .andWhere('p.quizId = :quizId', { quizId })
        .getOne(),

      this.userQuizAnswerRepo
        .createQueryBuilder('a')
        .select(['a.questionId', 'a.selectedAnswerId', 'q.orderIndex'])
        .leftJoin('a.question', 'q')
        .where('a.userId = :userId', { userId })
        .andWhere('a.quizId = :quizId', { quizId })
        .getMany(),

      this.questionRepo
        .createQueryBuilder('q')
        .where('q.quizId = :quizId', { quizId })
        .getCount(),
    ]);

    let pausedIndex = progress?.pausedAtQuestionIndex ?? 0;
    let currentPage = 1;

    const isCompleted =
      progress?.status === QuizProgressStatus.COMPLETED ||
      progress?.passed === true ||
      progress?.status === QuizProgressStatus.TIMEOUT;

    if (userAnswers.length > 0 && !isCompleted) {
      const nextQuestionSeclected = userAnswers.find(
        ({ question: { orderIndex } }) => orderIndex - 1 === pausedIndex + 1,
      );

      if (nextQuestionSeclected || pausedIndex + 1 === totalQuestions) {
        pausedIndex = Array.from({ length: totalQuestions }).findIndex(
          (_, i) =>
            !userAnswers.some(
              ({ question: { orderIndex } }) => orderIndex - 1 === i,
            ),
        );
      } else {
        pausedIndex += 1;
      }
      const questionsBefore = await this.questionRepo
        .createQueryBuilder('q')
        .where('q.quizId = :quizId', { quizId })
        .andWhere('q.orderIndex < :orderIndex', {
          orderIndex: pausedIndex + 1,
        })
        .getCount();

      currentPage = Math.floor(questionsBefore / limit) + 1;

      const totalPages = Math.ceil(totalQuestions / limit);
      if (currentPage > totalPages) currentPage = totalPages;
    } else {
      currentPage = 1;
      pausedIndex = 0;
    }

    const answers = userAnswers.map((a) => ({
      questionId: a.questionId,
      selectedAnswerId: a.selectedAnswerId,
      questionIndex: a.question.orderIndex - 1,
    }));

    return {
      pausedAt: pausedIndex,
      answers,
      currentPage,
    };
  }

  /**
   * Retrieves the names and IDs of all quizzes the user has passed.
   * @param userId - The UUID of the user
   * @returns List of passed quizzes with quizId and badgeTitle, sorted alphabetically by title
   */
  async getPassedQuizzesBadges(userId: string): Promise<
    {
      quizId: string;
      badgeTitle: string;
    }[]
  > {
    return this.userQuizProgressRepo
      .createQueryBuilder('progress')
      .select('progress.quizId', 'quizId')
      .addSelect('quiz.badgeTitle', 'badgeTitle')
      .innerJoin('progress.quiz', 'quiz')
      .where('progress.userId = :userId', { userId })
      .andWhere('progress.passed = :passed', { passed: true })
      .orderBy('quiz.title', 'ASC')
      .getRawMany<{
        quizId: string;
        badgeTitle: string;
      }>();
  }

  /**
   * Starts or restarts a quiz session for a user.
   * - If the user has COMPLETED or timed out: resets score to 0 and sets status to IN_PROGRESS
   * - Otherwise (first attempt or paused): only updates attemptAt and status
   * @param userId - The UUID of the user
   * @param quizId - The UUID of the quiz
   */
  async startQuiz(userId: string, quizId: string) {
    const userProgress = await this.userQuizProgressRepo.findOne({
      where: { userId, quizId },
    });

    if (
      userProgress?.status === QuizProgressStatus.COMPLETED ||
      userProgress?.status === QuizProgressStatus.TIMEOUT
    ) {
      await this.userQuizProgressRepo.upsert(
        {
          userId,
          quizId,
          status: QuizProgressStatus.IN_PROGRESS,
          attemptAt: new Date(),
          score: 0,
        },
        ['userId', 'quizId'],
      );
    } else {
      await this.userQuizProgressRepo.upsert(
        {
          userId,
          quizId,
          status: QuizProgressStatus.IN_PROGRESS,
          attemptAt: new Date(),
        },
        ['userId', 'quizId'],
      );
    }
  }

  /**
   * Saves a user's answer for a question and updates their quiz progress.
   * - Calculates score based on correct answers out of total questions
   * - Marks quiz as COMPLETED if this is the last question
   * - Sets passed to true if score is 100% on the last question
   * @param userId - The UUID of the user
   * @param quizId - The UUID of the quiz
   * @param questionId - The UUID of the question being answered
   * @param selectedAnswerId - The UUID of the selected answer
   * @returns score, passed, correctAnswers, totalQuestions, answeredQuestions, isLastQuestion, answerIsCorrect
   * @throws NotFoundException if the question doesn't belong to this quiz or answer not found
   * @throws BadRequestException if the quiz is not currently IN_PROGRESS
   * @returns Score, passed status, correct answers count, total questions, answered questions, and isLastQuestion flag
   */
  async insertUserProgress(
    userId: string,
    quizId: string,
    questionId: string,
    selectedAnswerId: string,
  ) {
    const progress = await this.userQuizProgressRepo.findOne({
      where: { userId, quizId },
    });

    const question = await this.questionRepo.findOne({
      where: {
        id: questionId,
        quizId,
      },
    });
    if (!question) {
      throw new NotFoundException('Question does not belong to this quiz');
    }

    const answer = await this.answerRepo.findOne({
      where: { id: selectedAnswerId, questionId },
    });

    if (!answer)
      throw new NotFoundException('Answer not found for this question');

    if (progress?.status !== QuizProgressStatus.IN_PROGRESS) {
      throw new BadRequestException('Quiz is not active');
    }

    await this.userQuizAnswerRepo.upsert(
      {
        userId,
        quizId,
        questionId,
        selectedAnswerId,
        isCorrect: answer?.isCorrect,
      },
      ['userId', 'quizId', 'questionId'],
    );

    const [totalQuestions, answeredQuestions, correctAnswers] =
      await Promise.all([
        this.questionRepo.count({ where: { quizId } }),
        this.userQuizAnswerRepo.count({ where: { userId, quizId } }),
        this.userQuizAnswerRepo.count({
          where: { userId, quizId, isCorrect: true },
        }),
      ]);

    const score = (correctAnswers / totalQuestions) * 100;
    const isLastQuestion = answeredQuestions === totalQuestions;
    const passed = isLastQuestion && score === 100;
    const userProgress = Math.round((answeredQuestions / totalQuestions) * 100);

    await this.userQuizProgressRepo.upsert(
      {
        userId,
        quizId,
        score,
        ...(passed ? { passed: true } : {}),
        status: isLastQuestion
          ? QuizProgressStatus.COMPLETED
          : QuizProgressStatus.IN_PROGRESS,
        completedAt: isLastQuestion ? new Date() : null,
        pausedAtQuestionIndex: question.orderIndex - 1,
        progress: isLastQuestion ? null : userProgress,
      },
      ['userId', 'quizId'],
    );

    return {
      score,
      passed,
      correctAnswers,
      totalQuestions,
      answeredQuestions,
      isLastQuestion,
      answerIsCorrect: answer?.isCorrect,
    };
  }

  /**
   * Deletes all submitted answers for a user on a specific quiz.
   * Only executes if the quiz is COMPLETED or TIMEOUT and the user has not passed.
   * @param userId - The UUID of the user
   * @param quizId - The UUID of the quiz
   * @throws NotFoundException if no progress record exists
   */
  async deleteUserAnswers(userId: string, quizId: string) {
    const progress = await this.userQuizProgressRepo.findOne({
      where: { userId, quizId },
    });

    if (!progress) throw new NotFoundException('progress not found');

    if (
      (progress.status === QuizProgressStatus.COMPLETED ||
        progress.status === QuizProgressStatus.TIMEOUT) &&
      !progress.passed
    ) {
      await this.userQuizAnswerRepo.delete({ userId, quizId });
    }
  }

  /**
   * Pauses a quiz session, saving the current question index and remaining time.
   * If remainingTimeSeconds is 0, the quiz is marked as TIMEOUT instead of PAUSED.
   * @param userId - The UUID of the user
   * @param quizId - The UUID of the quiz
   * @param pausedAtQuestionIndex - Zero-based index of the question the user paused on
   * @param remainingTimeSeconds - Remaining time in seconds at the point of pausing
   * @throws BadRequestException if remainingTimeSeconds is negative or quiz is not IN_PROGRESS
   * @throws NotFoundException if no progress record exists or question index is invalid
   */
  async pauseQuiz(
    userId: string,
    quizId: string,
    pausedAtQuestionIndex: number | undefined,
    remainingTimeSeconds: number,
  ) {
    if (remainingTimeSeconds < 0) {
      throw new BadRequestException('remainingTimeSeconds must be >= 0');
    }
    const progress = await this.userQuizProgressRepo.findOne({
      where: { userId, quizId },
    });

    if (!progress) {
      throw new NotFoundException('Quiz not started yet');
    }

    if (!(progress.status === QuizProgressStatus.IN_PROGRESS)) {
      throw new BadRequestException('Quiz is not active');
    }

    if (pausedAtQuestionIndex) {
      const question = await this.questionRepo.findOne({
        where: { orderIndex: pausedAtQuestionIndex + 1, quizId },
      });

      if (!question) {
        throw new NotFoundException('Question does not belong to this quiz');
      }
    }

    await this.userQuizProgressRepo.upsert(
      {
        userId,
        quizId,
        status:
          remainingTimeSeconds === 0
            ? QuizProgressStatus.TIMEOUT
            : QuizProgressStatus.PAUSED,
        pausedAtQuestionIndex:
          remainingTimeSeconds === 0 ? 0 : pausedAtQuestionIndex,
        remainingTimeSeconds,
      },
      ['userId', 'quizId'],
    );
  }

  /**
   * Retrieves all active quiz activities for a user from the last 2 days.
   * @param userId - The UUID of the user
   * @returns Progress records with status, score, passed, attemptAt, remainingTimeSeconds, and quiz info
   */
  async getActivities(userId: string) {
    const twoDaysAgo = new Date();
    twoDaysAgo.setDate(twoDaysAgo.getDate() - 2);

    return this.userQuizProgressRepo
      .createQueryBuilder('progress')
      .leftJoin('progress.quiz', 'quiz')
      .loadRelationCountAndMap('quiz.questionsCount', 'quiz.questions')
      .select([
        'progress.id',
        'progress.status',
        'progress.score',
        'progress.passed',
        'progress.attemptAt',
        'progress.remainingTimeSeconds',
        'progress.progress',
        'quiz.id',
        'quiz.title',
        'quiz.description',
        'quiz.timeInSeconds',
      ])
      .where('progress.userId = :userId', { userId })
      .andWhere('progress.attemptAt >= :twoDaysAgo', { twoDaysAgo })
      .orderBy('progress.attemptAt', 'DESC', 'NULLS LAST')
      .getMany();
  }

  /**
   * Retrieves aggregate statistics for a user across all their quiz attempts.
   * @param userId - The UUID of the user
   * @returns totalQuizzes attempted, passedQuizzes, averageScore, and totalScore
   */
  async getUserStats(userId: string) {
    const [passedResult, scoreResult, totalQuizzes]: [
      { passedQuizzes: string },
      { averageScore: string | null; totalScore: string | null },
      { total: string },
    ] = await Promise.all([
      this.userQuizProgressRepo
        .createQueryBuilder('progress')
        .select('COUNT(progress.quizId)', 'passedQuizzes')
        .where('progress.userId = :userId', { userId })
        .andWhere('progress.passed = :passed', { passed: true })
        .getRawOne(),

      this.userQuizProgressRepo
        .createQueryBuilder('progress')
        .select('AVG(progress.score)', 'averageScore')
        .addSelect('SUM(progress.score)', 'totalScore')
        .where('progress.userId = :userId', { userId })
        .getRawOne(),

      this.userQuizProgressRepo
        .createQueryBuilder('progress')
        .select('COUNT(DISTINCT progress.quizId)', 'total')
        .where('progress.userId = :userId', { userId })
        .getRawOne(),
    ]);

    return {
      totalQuizzes: parseInt(totalQuizzes.total ?? '0'),
      passedQuizzes: parseInt(passedResult.passedQuizzes ?? '0'),
      averageScore: parseInt(scoreResult?.averageScore ?? '0'),
      totalScore: parseInt(scoreResult?.totalScore ?? '0'),
    };
  }

  /**
   * Returns the top 3 users ranked by total score descending.
   * @returns Array of up to 3 entries with userId, name, and totalScore
   */
  async getTopThree(): Promise<LeaderboardEntry[]> {
    const result = await this.userRepo
      .createQueryBuilder('user')
      .select('user.id', 'userId')
      .addSelect('user.name', 'name')
      .addSelect('COALESCE(SUM(progress.score), 0)', 'totalScore')
      .leftJoin(UserQuizProgress, 'progress', 'progress.userId = user.id')
      .groupBy('user.id')
      .addGroupBy('user.name')
      .orderBy('"totalScore"', 'DESC')
      .limit(3)
      .getRawMany();

    return result.map((item) => ({
      ...item,
      totalScore: parseInt(item.totalScore),
    }));
  }

  /**
   * Returns the leaderboard rank and stats for a specific user.
   * Users with no quiz progress are included with zeroed stats and ranked at the bottom.
   * @param userId - The UUID of the user
   * @returns userId, name, totalScore, and rank position
   */
  async getUserRank(userId: string): Promise<UserRank> {
    const result = await this.userRepo
      .createQueryBuilder('user')
      .select('user.id', 'userId')
      .addSelect('user.name', 'name')
      .addSelect('COALESCE(SUM(progress.score), 0)', 'totalScore')
      .addSelect(
        `RANK() OVER (ORDER BY COALESCE(SUM(progress.score), 0) DESC)`,
        'rank',
      )
      .leftJoin(UserQuizProgress, 'progress', 'progress.userId = user.id')
      .where('user.id = :userId', { userId })
      .groupBy('user.id')
      .addGroupBy('user.name')
      .getRawOne();

    return {
      userId: result?.userId,
      rank: Number(result?.rank ?? 0),
      name: result?.name,
      totalScore: parseInt(result?.totalScore ?? 0),
    };
  }

  /**
   * Retrieves a paginated leaderboard of all users ordered by total score descending.
   * Users with no quiz progress are included with zeroed stats.
   * @param page - Page number (default: 1)
   * @param limit - Number of users per page (default: 10)
   * @returns Paginated data with userId, name, totalScore, and meta with page/limit/totalPages
   * @throws BadRequestException if page or limit is less than 1
   */
  async getLeaderboard(page: number = 1, limit: number = 10) {
    if (page < 1 || limit < 1) {
      throw new BadRequestException('page and limit must be >= 1');
    }

    const countResult = await this.userRepo
      .createQueryBuilder('user')
      .select('COUNT(DISTINCT user.id)', 'total')
      .getRawOne();
    const total = parseInt(countResult?.total) || 0;

    const data = await this.userRepo
      .createQueryBuilder('user')
      .select('user.id', 'userId')
      .addSelect('user.name', 'name')
      .addSelect('COALESCE(SUM(progress.score), 0)', 'totalScore')
      .leftJoin(UserQuizProgress, 'progress', 'progress.userId = user.id')
      .groupBy('user.id')
      .addGroupBy('user.name')
      .orderBy('"totalScore"', 'DESC')
      .offset((page - 1) * limit)
      .limit(limit)
      .getRawMany();

    return {
      data: data.map((item) => ({
        ...item,
        totalScore: parseInt(item.totalScore),
      })),
      meta: {
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }
}
