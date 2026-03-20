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

@Injectable()
export class QuizService {
  constructor(
    @InjectRepository(Quiz) private readonly quizRepo: Repository<Quiz>,
    @InjectRepository(Question)
    private readonly questionRepo: Repository<Question>,
    @InjectRepository(Answer) private readonly answerRepo: Repository<Answer>,
    @InjectRepository(UserQuizProgress)
    private readonly userQuizProgressRepo: Repository<UserQuizProgress>,
    @InjectRepository(UserQuizAnswer)
    private readonly userQuizAnswerRepo: Repository<UserQuizAnswer>,
  ) {}
  /**
   * Retrieves all quizzes with their progress status for a specific user.
   * @param userId - The ID of the user
   * @returns Object containing quizInfo (all quizzes) and quizzesStatus (user progress per quiz)
   */

  async getQuizzes(userId: string) {
    const info = await this.quizRepo.find({
      select: {
        id: true,
        title: true,
        description: true,
        timeInSeconds: true,
      },
    });

    const progress = await this.userQuizProgressRepo.find({
      where: { userId },
      select: ['quizId', 'score', 'status', 'passed'],
    });

    const quizzesStatus = progress.map((p) => ({
      quizId: p.quizId,
      score: p.score,
      status: p.status,
      passed: p.passed,
    }));

    return { quizInfo: info, quizzesStatus };
  }

  /**
   * Retrieves paginated questions for a specific quiz, including their answers.
   * @param quizId - The ID of the quiz
   * @param page - Page number (default: 1)
   * @param limit - Number of questions per page (default: 10)
   * @returns Paginated list of questions with answers ordered by orderIndex
   */
  async getQuestionsByQuiz(
    quizId: string,
    page: number = 1,
    limit: number = 10,
  ) {
    if (page < 1 || limit < 1) {
      throw new BadRequestException('page and limit must be >= 1');
    }
    const skip = (page - 1) * limit;

    const [questions, total] = await this.questionRepo
      .createQueryBuilder('question')
      .where('question.quizId = :quizId', { quizId })
      .orderBy('question.orderIndex', 'ASC')
      .skip(skip)
      .take(limit)
      .getManyAndCount();

    return {
      data: questions,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Retrieves all answers for a specific question ordered by orderIndex.
   * @param questionId - The ID of the question
   * @returns List of answers for the question
   */
  async getAnswersByQuestion(questionId: string) {
    return this.answerRepo
      .createQueryBuilder('answer')
      .select(['answer.id', 'answer.text', 'answer.orderIndex'])
      .where('answer.questionId = :questionId', { questionId })
      .orderBy('answer.orderIndex', 'ASC')
      .getMany();
  }

  /**
   * Retrieves the names and IDs of all quizzes a user has passed.
   * @param userId - The ID of the user
   * @returns List of passed quizzes with their IDs and titles
   */
  async getPassedQuizzesNames(userId: string) {
    return await this.userQuizProgressRepo
      .createQueryBuilder('progress')
      .select('progress.quizId', 'quizId')
      .addSelect('quiz.title', 'quizTitle')
      .innerJoin('progress.quiz', 'quiz')
      .where('progress.userId = :userId', { userId })
      .andWhere('progress.passed = :passed', { passed: true })
      .getRawMany();
  }

  /**
   * Retrieves a user's answer for a specific question including question and selected answer details.
   * @param userId - The ID of the user
   * @param questionId - The ID of the question
   * @returns The user's answer with question and selected answer relations
   */
  async getUserQuizAnswer(userId: string, questionId: string) {
    return await this.userQuizAnswerRepo.findOne({
      where: { userId, questionId },
      relations: ['question', 'selectedAnswer'],
    });
  }

  /**
   * Retrieves a user's progress for a specific quiz including quiz and paused question details.
   * @param userId - The ID of the user
   * @param quizId - The ID of the quiz
   * @returns The user's quiz progress with quiz and pausedAtQuestion relations
   */
  async getQuizProgress(userId: string, quizId: string) {
    return await this.userQuizProgressRepo.findOne({
      where: { userId, quizId },
      relations: ['quiz', 'pausedAtQuestion'],
    });
  }

  /**
   * Starts or restarts a quiz session for a user.
   * - If user already passed, only updates attemptAt without resetting progress
   * - If user has not passed, resets all progress fields and records attempt time
   * @param userId - The ID of the user
   * @param quizId - The ID of the quiz
   */
  async startQuiz(userId: string, quizId: string) {
    const progress = await this.userQuizProgressRepo.findOne({
      where: { userId, quizId },
    });

    if (progress?.passed) {
      await this.userQuizProgressRepo.update(
        { userId, quizId },
        { attemptAt: new Date(), status: QuizProgressStatus.IN_PROGRESS },
      );
      return;
    }

    await this.userQuizProgressRepo.upsert(
      {
        userId,
        quizId,
        status: QuizProgressStatus.IN_PROGRESS,
        score: null,
        passed: false,
        pausedAtQuestionId: null,
        remainingTimeSeconds: null,
        completedAt: null,
        attemptAt: new Date(),
      },
      ['userId', 'quizId'],
    );
  }

  /**
   * Saves a user's answer for a question and updates their quiz progress.
   * - Calculates score based on correct answers so far
   * - Marks quiz as COMPLETED if it's the last question
   * - Deletes all answers if user passed (score === 100%)
   * - Skips updating score and passed status if user already passed
   * @param userId - The ID of the user
   * @param quizId - The ID of the quiz
   * @param questionId - The ID of the question being answered
   * @param selectedAnswerId - The ID of the selected answer
   * @throws NotFoundException if answer not found
   * @throws BadRequestException if quiz not started yet
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

    const questionExists = await this.questionRepo.findOne({
      where: {
        id: questionId,
        quizId,
      },
    });
    if (!questionExists) {
      throw new NotFoundException('Question does not belong to this quiz');
    }

    const answer = await this.answerRepo.findOne({
      where: { id: selectedAnswerId, questionId },
    });

    if (!answer)
      throw new NotFoundException('Answer not found for this question');

    if (!progress) throw new BadRequestException('Quiz not started yet');

    if (progress.status !== QuizProgressStatus.IN_PROGRESS) {
      throw new BadRequestException('Quiz is not active');
    }

    const existingAnswer = await this.userQuizAnswerRepo.findOne({
      where: { userId, quizId, questionId },
    });
    if (existingAnswer) {
      throw new BadRequestException('Question already answered');
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

    if (totalQuestions === 0) {
      throw new BadRequestException('Quiz has no questions');
    }

    const score = (correctAnswers / totalQuestions) * 100;
    const isLastQuestion = answeredQuestions === totalQuestions;
    const passed = isLastQuestion && score === 100;

    await this.userQuizProgressRepo.upsert(
      {
        userId,
        quizId,
        ...(progress?.passed ? {} : { score, passed }),
        status: isLastQuestion
          ? QuizProgressStatus.COMPLETED
          : QuizProgressStatus.IN_PROGRESS,
        completedAt: isLastQuestion ? new Date() : null,
        pausedAtQuestionId: questionId,
      },
      ['userId', 'quizId'],
    );

    if (isLastQuestion || passed) {
      await this.userQuizAnswerRepo.delete({ userId, quizId });
    }

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
   * Pauses a quiz session for a user saving the current question and remaining time.
   * @param userId - The ID of the user
   * @param quizId - The ID of the quiz
   * @param pausedAtQuestionId - The ID of the question the user paused at
   * @param remainingTimeSeconds - The remaining time in seconds when the user paused
   * @throws NotFoundException if quiz progress not found
   */

  async pauseQuiz(
    userId: string,
    quizId: string,
    pausedAtQuestionId: string,
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

    if (progress.status !== QuizProgressStatus.IN_PROGRESS) {
      throw new BadRequestException('Quiz is not active');
    }

    if (pausedAtQuestionId) {
      const question = await this.questionRepo.findOne({
        where: { id: pausedAtQuestionId, quizId },
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
        pausedAtQuestionId,
        remainingTimeSeconds,
      },
      ['userId', 'quizId'],
    );
  }

  /**
   * Retrieves statistics for a specific user.
   * - Total quizzes in the app
   * - Number of passed quizzes
   * - Average score across passed quizzes
   * - Total score across passed quizzes
   * @param userId - The ID of the user
   * @returns User stats including totalQuizzes, passedQuizzes, averageScore, and totalScore
   */
  async getUserStats(userId: string) {
    const [result, totalQuizzes] = await Promise.all([
      this.userQuizProgressRepo
        .createQueryBuilder('progress')
        .select('COUNT(progress.quizId)', 'passedQuizzes')
        .addSelect('AVG(progress.score)', 'averageScore')
        .addSelect('SUM(progress.score)', 'totalScore')
        .where('progress.userId = :userId', { userId })
        .andWhere('progress.passed = :passed', { passed: true })
        .getRawOne(),

      this.quizRepo.count(),
    ]);

    return {
      totalQuizzes,
      passedQuizzes: parseInt(result.passedQuizzes) || 0,
      averageScore: parseFloat(result.averageScore) || 0,
      totalScore: parseFloat(result.totalScore) || 0,
    };
  }

  /**
   * Retrieves the leaderboard of users ordered by passed quizzes and average score.
   * @param page - Page number (default: 1)
   * @param limit - Number of users per page (default: 10)
   * @returns Paginated leaderboard with userId, name, passedQuizzes, averageScore, and totalScore
   */
  async getLeaderboard(page: number = 1, limit: number = 10) {
    if (page < 1 || limit < 1) {
      throw new BadRequestException('page and limit must be >= 1');
    }
    const countResult = await this.userQuizProgressRepo
      .createQueryBuilder('progress')
      .select('COUNT(DISTINCT progress.userId)', 'total')
      .innerJoin(User, 'user', 'user.id = progress.userId')
      .where('progress.passed = :passed', { passed: true })
      .getRawOne();
    const total = parseInt(countResult?.total) || 0;

    const data = await this.userQuizProgressRepo
      .createQueryBuilder('progress')
      .select('progress.userId', 'userId')
      .addSelect('user.name', 'name')
      .addSelect('COUNT(progress.quizId)', 'passedQuizzes')
      .addSelect('AVG(progress.score)', 'averageScore')
      .addSelect('SUM(progress.score)', 'totalScore')
      .innerJoin(User, 'user', 'user.id = progress.userId')
      .where('progress.passed = :passed', { passed: true })
      .groupBy('progress.userId')
      .addGroupBy('user.name')
      .orderBy('"passedQuizzes"', 'DESC')
      .addOrderBy('"averageScore"', 'DESC')
      .offset((page - 1) * limit)
      .limit(limit)
      .getRawMany();

    return {
      data: data.map((item) => ({
        ...item,
        passedQuizzes: parseInt(item.passedQuizzes),
        averageScore: parseFloat(item.averageScore),
        totalScore: parseFloat(item.totalScore),
      })),
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }
}
