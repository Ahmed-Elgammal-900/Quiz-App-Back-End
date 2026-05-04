import { Test, TestingModule } from '@nestjs/testing';
import { QuizService } from './quiz.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Quiz } from './entities/quiz.entity';
import { Question } from './entities/question.entity';
import { Answer } from './entities/answer.entity';
import { UserQuizProgress } from './entities/user-progress.entity';
import { UserQuizAnswer } from './entities/user-quiz-answer.entity';
import { User } from '../user/entities/user.entity';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { QuizProgressStatus } from './constants/quiz-progress-status';

const mockRepo = () => ({
  find: jest.fn(),
  findOne: jest.fn(),
  count: jest.fn(),
  save: jest.fn(),
  update: jest.fn(),
  delete: jest.fn(),
  upsert: jest.fn(),
  createQueryBuilder: jest.fn().mockReturnValue({
    select: jest.fn().mockReturnThis(),
    addSelect: jest.fn().mockReturnThis(),
    leftJoin: jest.fn().mockReturnThis(),
    innerJoin: jest.fn().mockReturnThis(),
    leftJoinAndSelect: jest.fn().mockReturnThis(),
    innerJoinAndSelect: jest.fn().mockReturnThis(),
    loadRelationCountAndMap: jest.fn().mockReturnThis(),
    where: jest.fn().mockReturnThis(),
    andWhere: jest.fn().mockReturnThis(),
    groupBy: jest.fn().mockReturnThis(),
    addGroupBy: jest.fn().mockReturnThis(),
    orderBy: jest.fn().mockReturnThis(),
    addOrderBy: jest.fn().mockReturnThis(),
    offset: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    skip: jest.fn().mockReturnThis(),
    take: jest.fn().mockReturnThis(),
    getOne: jest.fn(),
    getMany: jest.fn(),
    getCount: jest.fn(),
    getRawOne: jest.fn(),
    getRawMany: jest.fn(),
    getManyAndCount: jest.fn(),
  }),
});

describe('QuizService', () => {
  let service: QuizService;
  let quizRepo: ReturnType<typeof mockRepo>;
  let questionRepo: ReturnType<typeof mockRepo>;
  let answerRepo: ReturnType<typeof mockRepo>;
  let userQuizProgressRepo: ReturnType<typeof mockRepo>;
  let userQuizAnswerRepo: ReturnType<typeof mockRepo>;
  let userRepo: ReturnType<typeof mockRepo>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        QuizService,
        { provide: getRepositoryToken(Quiz), useFactory: mockRepo },
        { provide: getRepositoryToken(Question), useFactory: mockRepo },
        { provide: getRepositoryToken(Answer), useFactory: mockRepo },
        { provide: getRepositoryToken(UserQuizProgress), useFactory: mockRepo },
        { provide: getRepositoryToken(UserQuizAnswer), useFactory: mockRepo },
        { provide: getRepositoryToken(User), useFactory: mockRepo },
      ],
    }).compile();

    service = module.get<QuizService>(QuizService);
    quizRepo = module.get(getRepositoryToken(Quiz));
    questionRepo = module.get(getRepositoryToken(Question));
    answerRepo = module.get(getRepositoryToken(Answer));
    userQuizProgressRepo = module.get(getRepositoryToken(UserQuizProgress));
    userQuizAnswerRepo = module.get(getRepositoryToken(UserQuizAnswer));
    userRepo = module.get(getRepositoryToken(User));
  });

  describe('startQuiz', () => {
    it('should upsert IN_PROGRESS with no score reset when no prior progress', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue(null);
      userQuizProgressRepo.upsert.mockResolvedValue(null);

      await service.startQuiz('user-id', 'quiz-id');

      expect(userQuizProgressRepo.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-id',
          quizId: 'quiz-id',
          status: QuizProgressStatus.IN_PROGRESS,
          attemptAt: expect.any(Date),
        }),
        ['userId', 'quizId'],
      );
      // score should NOT be reset for a fresh/paused user
      expect(userQuizProgressRepo.upsert).not.toHaveBeenCalledWith(
        expect.objectContaining({ score: 0 }),
        expect.anything(),
      );
    });

    it('should reset score to 0 when prior attempt was COMPLETED', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.COMPLETED,
      });
      userQuizProgressRepo.upsert.mockResolvedValue(null);

      await service.startQuiz('user-id', 'quiz-id');

      expect(userQuizProgressRepo.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-id',
          quizId: 'quiz-id',
          status: QuizProgressStatus.IN_PROGRESS,
          score: 0,
          attemptAt: expect.any(Date),
        }),
        ['userId', 'quizId'],
      );
    });

    it('should reset score to 0 when prior attempt was TIMEOUT', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.TIMEOUT,
      });
      userQuizProgressRepo.upsert.mockResolvedValue(null);

      await service.startQuiz('user-id', 'quiz-id');

      expect(userQuizProgressRepo.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          score: 0,
          status: QuizProgressStatus.IN_PROGRESS,
        }),
        ['userId', 'quizId'],
      );
    });
  });

  describe('insertUserProgress', () => {
    it('should throw NotFoundException if question does not belong to quiz', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.IN_PROGRESS,
      });
      questionRepo.findOne.mockResolvedValue(null);

      await expect(
        service.insertUserProgress('user-id', 'quiz-id', 'q-id', 'a-id'),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException if answer not found for question', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.IN_PROGRESS,
      });
      questionRepo.findOne.mockResolvedValue({
        id: 'q-id',
        quizId: 'quiz-id',
        orderIndex: 1,
      });
      answerRepo.findOne.mockResolvedValue(null);

      await expect(
        service.insertUserProgress('user-id', 'quiz-id', 'q-id', 'a-id'),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException if quiz is not IN_PROGRESS', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue(null);
      questionRepo.findOne.mockResolvedValue({
        id: 'q-id',
        quizId: 'quiz-id',
        orderIndex: 1,
      });
      answerRepo.findOne.mockResolvedValue({ isCorrect: true });

      await expect(
        service.insertUserProgress('user-id', 'quiz-id', 'q-id', 'a-id'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should calculate score correctly when not last question', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.IN_PROGRESS,
      });
      questionRepo.findOne.mockResolvedValue({
        id: 'q-id',
        quizId: 'quiz-id',
        orderIndex: 1,
      });
      answerRepo.findOne.mockResolvedValue({ isCorrect: true });
      userQuizAnswerRepo.upsert.mockResolvedValue(null);
      userQuizProgressRepo.upsert.mockResolvedValue(null);

      // Promise.all order: [totalQuestions, answeredQuestions, correctAnswers]
      questionRepo.count.mockResolvedValue(10);
      userQuizAnswerRepo.count
        .mockResolvedValueOnce(5)
        .mockResolvedValueOnce(4);

      const result = await service.insertUserProgress(
        'user-id',
        'quiz-id',
        'q-id',
        'a-id',
      );

      expect(result.score).toBe(40);
      expect(result.isLastQuestion).toBe(false);
      expect(result.passed).toBe(false);
      expect(result.correctAnswers).toBe(4);
      expect(result.totalQuestions).toBe(10);
    });

    it('should mark as COMPLETED and passed when last question is correct', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.IN_PROGRESS,
      });
      questionRepo.findOne.mockResolvedValue({
        id: 'q-id',
        quizId: 'quiz-id',
        orderIndex: 10,
      });
      answerRepo.findOne.mockResolvedValue({ isCorrect: true });
      userQuizAnswerRepo.upsert.mockResolvedValue(null);
      userQuizProgressRepo.upsert.mockResolvedValue(null);

      questionRepo.count.mockResolvedValue(10);
      userQuizAnswerRepo.count
        .mockResolvedValueOnce(10)
        .mockResolvedValueOnce(10);

      const result = await service.insertUserProgress(
        'user-id',
        'quiz-id',
        'q-id',
        'a-id',
      );

      expect(result.passed).toBe(true);
      expect(result.isLastQuestion).toBe(true);
      expect(result.score).toBe(100);

      expect(userQuizProgressRepo.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          status: QuizProgressStatus.COMPLETED,
          passed: true,
          completedAt: expect.any(Date),
        }),
        ['userId', 'quizId'],
      );
    });

    it('should mark as COMPLETED but not passed when last question is wrong', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.IN_PROGRESS,
      });
      questionRepo.findOne.mockResolvedValue({
        id: 'q-id',
        quizId: 'quiz-id',
        orderIndex: 10,
      });
      answerRepo.findOne.mockResolvedValue({ isCorrect: false });
      userQuizAnswerRepo.upsert.mockResolvedValue(null);
      userQuizProgressRepo.upsert.mockResolvedValue(null);

      questionRepo.count.mockResolvedValue(10);
      userQuizAnswerRepo.count
        .mockResolvedValueOnce(10)
        .mockResolvedValueOnce(9);

      const result = await service.insertUserProgress(
        'user-id',
        'quiz-id',
        'q-id',
        'a-id',
      );

      expect(result.passed).toBe(false);
      expect(result.isLastQuestion).toBe(true);
      expect(result.score).toBe(90);

      expect(userQuizProgressRepo.upsert).toHaveBeenCalledWith(
        expect.objectContaining({ status: QuizProgressStatus.COMPLETED }),
        ['userId', 'quizId'],
      );
    });
  });

  describe('deleteUserAnswers', () => {
    it('should throw NotFoundException if no progress record exists', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue(null);

      await expect(
        service.deleteUserAnswers('user-id', 'quiz-id'),
      ).rejects.toThrow(NotFoundException);
    });

    it('should delete answers if quiz is COMPLETED and not passed', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.COMPLETED,
        passed: false,
      });
      userQuizAnswerRepo.delete.mockResolvedValue(null);

      await service.deleteUserAnswers('user-id', 'quiz-id');

      expect(userQuizAnswerRepo.delete).toHaveBeenCalledWith({
        userId: 'user-id',
        quizId: 'quiz-id',
      });
    });

    it('should delete answers if quiz is TIMEOUT and not passed', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.TIMEOUT,
        passed: false,
      });
      userQuizAnswerRepo.delete.mockResolvedValue(null);

      await service.deleteUserAnswers('user-id', 'quiz-id');

      expect(userQuizAnswerRepo.delete).toHaveBeenCalledWith({
        userId: 'user-id',
        quizId: 'quiz-id',
      });
    });

    it('should not delete answers if user passed', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.COMPLETED,
        passed: true,
      });

      await service.deleteUserAnswers('user-id', 'quiz-id');

      expect(userQuizAnswerRepo.delete).not.toHaveBeenCalled();
    });
  });

  describe('getResult', () => {
    it('should throw NotFoundException if progress not found', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue(null);

      await expect(service.getResult('user-id', 'quiz-id')).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw NotFoundException if quiz not found', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        score: 80,
        status: QuizProgressStatus.COMPLETED,
        passed: true,
        remainingTimeSeconds: 0,
      });
      userQuizAnswerRepo.count.mockResolvedValue(8);
      questionRepo.count.mockResolvedValue(10);
      quizRepo.findOne.mockResolvedValue(null);

      await expect(service.getResult('user-id', 'quiz-id')).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should return full result with correct timeTaken', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        score: 80,
        status: QuizProgressStatus.COMPLETED,
        passed: false,
        remainingTimeSeconds: 30,
      });
      userQuizAnswerRepo.count.mockResolvedValue(8);
      questionRepo.count.mockResolvedValue(10);
      quizRepo.findOne.mockResolvedValue({
        title: 'JS Quiz',
        timeInSeconds: 120,
      });

      const result = await service.getResult('user-id', 'quiz-id');

      expect(result).toEqual({
        quizTitle: 'JS Quiz',
        score: 80,
        status: QuizProgressStatus.COMPLETED,
        passed: false,
        correctAnswers: 8,
        totalQuestions: 10,
        timeTaken: 90,
      });
    });

    it('should use full timeInSeconds as timeTaken when remainingTime is 0', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        score: 50,
        status: QuizProgressStatus.TIMEOUT,
        passed: false,
        remainingTimeSeconds: 0,
      });
      userQuizAnswerRepo.count.mockResolvedValue(5);
      questionRepo.count.mockResolvedValue(10);
      quizRepo.findOne.mockResolvedValue({
        title: 'JS Quiz',
        timeInSeconds: 120,
      });

      const result = await service.getResult('user-id', 'quiz-id');

      expect(result.timeTaken).toBe(120);
    });
  });

  describe('pauseQuiz', () => {
    it('should throw NotFoundException if quiz not started', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue(null);

      await expect(
        service.pauseQuiz('user-id', 'quiz-id', 2, 270),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException if quiz is not IN_PROGRESS', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.PAUSED,
      });

      await expect(
        service.pauseQuiz('user-id', 'quiz-id', 2, 270),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException if remainingTimeSeconds is negative', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.IN_PROGRESS,
      });

      await expect(
        service.pauseQuiz('user-id', 'quiz-id', 2, -1),
      ).rejects.toThrow(BadRequestException);
    });

    it('should upsert PAUSED status with correct question index and remaining time', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.IN_PROGRESS,
      });
      questionRepo.findOne.mockResolvedValue({ id: 'q-id', orderIndex: 3 });
      userQuizProgressRepo.upsert.mockResolvedValue(null);

      await service.pauseQuiz('user-id', 'quiz-id', 2, 270);

      expect(userQuizProgressRepo.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          status: QuizProgressStatus.PAUSED,
          pausedAtQuestionIndex: 2,
          remainingTimeSeconds: 270,
        }),
        ['userId', 'quizId'],
      );
    });

    it('should upsert TIMEOUT status and reset pausedAtQuestionIndex when remainingTime is 0', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        status: QuizProgressStatus.IN_PROGRESS,
      });
      userQuizProgressRepo.upsert.mockResolvedValue(null);

      await service.pauseQuiz('user-id', 'quiz-id', undefined, 0);

      expect(userQuizProgressRepo.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          status: QuizProgressStatus.TIMEOUT,
          remainingTimeSeconds: 0,
          pausedAtQuestionIndex: 0,
        }),
        ['userId', 'quizId'],
      );
    });
  });

  describe('getActivities', () => {
    it('should return activities via query builder', async () => {
      const mockActivities = [
        {
          id: 'uuid-1',
          status: QuizProgressStatus.IN_PROGRESS,
          quiz: { title: 'JavaScript Basics' },
        },
        {
          id: 'uuid-2',
          status: QuizProgressStatus.PAUSED,
          quiz: { title: 'TypeScript Advanced' },
        },
      ];

      userQuizProgressRepo
        .createQueryBuilder()
        .getMany.mockResolvedValue(mockActivities);

      const result = await service.getActivities('user-id');

      expect(result).toHaveLength(2);
      expect(result[0].status).toBe(QuizProgressStatus.IN_PROGRESS);
    });

    it('should return empty array if no active activities', async () => {
      userQuizProgressRepo.createQueryBuilder().getMany.mockResolvedValue([]);

      const result = await service.getActivities('user-id');

      expect(result).toEqual([]);
    });
  });

  describe('getPassedQuizzesBadges', () => {
    it('should return passed quiz badges', async () => {
      const mockPassed = [
        { quizId: 'quiz-1', badgeTitle: 'JavaScript Master' },
        { quizId: 'quiz-2', badgeTitle: 'TypeScript Pro' },
      ];

      userQuizProgressRepo
        .createQueryBuilder()
        .getRawMany.mockResolvedValue(mockPassed);

      const result = await service.getPassedQuizzesBadges('user-id');

      expect(result).toEqual(mockPassed);
    });

    it('should return empty array if no passed quizzes', async () => {
      userQuizProgressRepo
        .createQueryBuilder()
        .getRawMany.mockResolvedValue([]);

      const result = await service.getPassedQuizzesBadges('user-id');

      expect(result).toEqual([]);
    });
  });

  describe('getUserStats', () => {
    it('should return parsed user stats', async () => {
      const qb = userQuizProgressRepo.createQueryBuilder();

      // Promise.all order: [passedResult, scoreResult, totalQuizzes]
      qb.getRawOne
        .mockResolvedValueOnce({ passedQuizzes: '5' })
        .mockResolvedValueOnce({ averageScore: '88.50', totalScore: '442.50' })
        .mockResolvedValueOnce({ total: '20' });

      const result = await service.getUserStats('user-id');

      expect(result).toEqual({
        totalQuizzes: 20,
        passedQuizzes: 5,
        averageScore: 88,
        totalScore: 442,
      });
    });

    it('should return zeros when user has no progress', async () => {
      const qb = userQuizProgressRepo.createQueryBuilder();

      qb.getRawOne
        .mockResolvedValueOnce({ passedQuizzes: null })
        .mockResolvedValueOnce({ averageScore: null, totalScore: null })
        .mockResolvedValueOnce({ total: null });

      const result = await service.getUserStats('user-id');

      expect(result).toEqual({
        totalQuizzes: 0,
        passedQuizzes: 0,
        averageScore: 0,
        totalScore: 0,
      });
    });
  });

  describe('getTopThree', () => {
    it('should return top 3 users with parsed totalScore', async () => {
      const mockData = [
        { userId: 'u-1', name: 'Alice', totalScore: '950' },
        { userId: 'u-2', name: 'Bob', totalScore: '800' },
        { userId: 'u-3', name: 'Carol', totalScore: '750' },
      ];

      userRepo.createQueryBuilder().getRawMany.mockResolvedValue(mockData);

      const result = await service.getTopThree();

      expect(result).toHaveLength(3);
      expect(result[0].totalScore).toBe(950);
      expect(result[1].totalScore).toBe(800);
    });

    it('should return empty array if no users', async () => {
      userRepo.createQueryBuilder().getRawMany.mockResolvedValue([]);

      const result = await service.getTopThree();

      expect(result).toEqual([]);
    });
  });

  describe('getUserRank', () => {
    it('should return rank and stats for the user', async () => {
      userRepo.createQueryBuilder().getRawOne.mockResolvedValue({
        userId: 'u-1',
        name: 'Alice',
        totalScore: '450',
        rank: '3',
      });

      const result = await service.getUserRank('u-1');

      expect(result).toEqual({
        userId: 'u-1',
        name: 'Alice',
        totalScore: 450,
        rank: 3,
      });
    });

    it('should return zeroed stats if user has no progress', async () => {
      userRepo.createQueryBuilder().getRawOne.mockResolvedValue({
        userId: 'u-1',
        name: 'Alice',
        totalScore: '0',
        rank: '10',
      });

      const result = await service.getUserRank('u-1');

      expect(result.totalScore).toBe(0);
      expect(result.rank).toBe(10);
    });
  });

  describe('getLeaderboard', () => {
    it('should throw BadRequestException if page < 1', async () => {
      await expect(service.getLeaderboard(0, 10)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw BadRequestException if limit < 1', async () => {
      await expect(service.getLeaderboard(1, 0)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should return paginated leaderboard with parsed scores', async () => {
      const qb = userRepo.createQueryBuilder();
      qb.getRawOne.mockResolvedValue({ total: '50' });
      qb.getRawMany.mockResolvedValue([
        { userId: 'u-1', name: 'Alice', totalScore: '900' },
        { userId: 'u-2', name: 'Bob', totalScore: '800' },
      ]);

      const result = await service.getLeaderboard(1, 10);

      expect(result.data).toHaveLength(2);
      expect(result.data[0].totalScore).toBe(900);
      expect(result.meta).toEqual({ page: 1, limit: 10, totalPages: 5 });
    });
  });
});
