import { Test, TestingModule } from '@nestjs/testing';
import { QuizService } from './quiz.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Quiz } from './entities/quiz.entity';
import { Question } from './entities/question.entity';
import { Answer } from './entities/answer.entity';
import { UserQuizProgress } from './entities/user-progress.entity';
import { UserQuizAnswer } from './entities/user-quiz-answer.entity';
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
    innerJoin: jest.fn().mockReturnThis(),
    leftJoinAndSelect: jest.fn().mockReturnThis(),
    innerJoinAndSelect: jest.fn().mockReturnThis(),
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

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        QuizService,
        { provide: getRepositoryToken(Quiz), useFactory: mockRepo },
        { provide: getRepositoryToken(Question), useFactory: mockRepo },
        { provide: getRepositoryToken(Answer), useFactory: mockRepo },
        { provide: getRepositoryToken(UserQuizProgress), useFactory: mockRepo },
        { provide: getRepositoryToken(UserQuizAnswer), useFactory: mockRepo },
      ],
    }).compile();

    service = module.get<QuizService>(QuizService);
    quizRepo = module.get(getRepositoryToken(Quiz));
    questionRepo = module.get(getRepositoryToken(Question));
    answerRepo = module.get(getRepositoryToken(Answer));
    userQuizProgressRepo = module.get(getRepositoryToken(UserQuizProgress));
    userQuizAnswerRepo = module.get(getRepositoryToken(UserQuizAnswer));
  });

  describe('startQuiz', () => {
    it('should reset progress if user has not passed', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue(null);
      userQuizProgressRepo.upsert.mockResolvedValue(null);

      await service.startQuiz('user-id', 'quiz-id');

      expect(userQuizProgressRepo.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-id',
          quizId: 'quiz-id',
          status: QuizProgressStatus.IN_PROGRESS,
          passed: false,
          score: null,
          pausedAtQuestionId: null,
          remainingTimeSeconds: null,
          completedAt: null,
          attemptAt: expect.any(Date),
        }),
        ['userId', 'quizId'],
      );

      expect(userQuizProgressRepo.update).not.toHaveBeenCalled();
    });

    it('should only update attemptAt and status if user already passed', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({ passed: true });
      userQuizProgressRepo.update.mockResolvedValue(null);

      await service.startQuiz('user-id', 'quiz-id');

      expect(userQuizProgressRepo.update).toHaveBeenCalledWith(
        {
          userId: 'user-id',
          quizId: 'quiz-id',
        },
        expect.objectContaining({
          attemptAt: expect.any(Date),
          status: QuizProgressStatus.IN_PROGRESS,
        }),
      );

      expect(userQuizProgressRepo.upsert).not.toHaveBeenCalled();
    });
  });

  describe('insertUserProgress', () => {
    it('should throw NotFoundException if question does not belong to quiz', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({ passed: false });
      questionRepo.findOne.mockResolvedValue(null);

      await expect(
        service.insertUserProgress('user-id', 'quiz-id', 'q-id', 'a-id'),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException if answer not found', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({ passed: false });
      questionRepo.findOne.mockResolvedValue({ id: 'q-id', quizId: 'quiz-id' });
      answerRepo.findOne.mockResolvedValue(null);

      await expect(
        service.insertUserProgress('user-id', 'quiz-id', 'q-id', 'a-id'),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException if quiz not started', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue(null);
      questionRepo.findOne.mockResolvedValue({ id: 'q-id', quizId: 'quiz-id' });
      answerRepo.findOne.mockResolvedValue({ isCorrect: true });

      await expect(
        service.insertUserProgress('user-id', 'quiz-id', 'q-id', 'a-id'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should calculate score correctly', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        passed: false,
        status: QuizProgressStatus.IN_PROGRESS,
      });
      questionRepo.findOne.mockResolvedValue({ id: 'q-id', quizId: 'quiz-id' });
      answerRepo.findOne.mockResolvedValue({ isCorrect: true });
      userQuizAnswerRepo.upsert.mockResolvedValue(null);
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
    });

    it('should mark as completed and passed on last correct question', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        passed: false,
        status: QuizProgressStatus.IN_PROGRESS,
      });
      questionRepo.findOne.mockResolvedValue({ id: 'q-id', quizId: 'quiz-id' });
      answerRepo.findOne.mockResolvedValue({ isCorrect: true });
      userQuizAnswerRepo.upsert.mockResolvedValue(null);
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
      expect(userQuizAnswerRepo.delete).toHaveBeenCalledWith({
        userId: 'user-id',
        quizId: 'quiz-id',
      });
    });

    it('should not update score if user already passed', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        passed: true,
        status: QuizProgressStatus.IN_PROGRESS,
      });
      questionRepo.findOne.mockResolvedValue({ id: 'q-id', quizId: 'quiz-id' });
      answerRepo.findOne.mockResolvedValue({ isCorrect: true });
      userQuizAnswerRepo.upsert.mockResolvedValue(null);
      questionRepo.count.mockResolvedValue(10);
      userQuizAnswerRepo.count
        .mockResolvedValueOnce(10)
        .mockResolvedValueOnce(10);

      await service.insertUserProgress('user-id', 'quiz-id', 'q-id', 'a-id');

      expect(userQuizProgressRepo.upsert).toHaveBeenCalledWith(
        expect.not.objectContaining({ score: expect.anything() }),
        ['userId', 'quizId'],
      );
    });
  });

  describe('pauseQuiz', () => {
    it('should save paused status with remaining time', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        userId: 'user-id',
        quizId: 'quiz-id',
        status: QuizProgressStatus.IN_PROGRESS,
      });
      questionRepo.findOne.mockResolvedValue({ id: 'q-id', quizId: 'quiz-id' });
      userQuizProgressRepo.upsert.mockResolvedValue(null);

      await service.pauseQuiz('user-id', 'quiz-id', 'q-id', 270);

      expect(userQuizProgressRepo.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          status: QuizProgressStatus.PAUSED,
          remainingTimeSeconds: 270,
          pausedAtQuestionId: 'q-id',
        }),
        ['userId', 'quizId'],
      );
    });

    it('should throw NotFoundException if quiz not started', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue(null);

      await expect(
        service.pauseQuiz('user-id', 'quiz-id', 'q-id', 270),
      ).rejects.toThrow(NotFoundException);
    });

    it('should save timeout status when remainingTimeSeconds is 0', async () => {
      userQuizProgressRepo.findOne.mockResolvedValue({
        userId: 'user-id',
        quizId: 'quiz-id',
        status: QuizProgressStatus.IN_PROGRESS,
      });
      questionRepo.findOne.mockResolvedValue({ id: 'q-id', quizId: 'quiz-id' });
      userQuizProgressRepo.upsert.mockResolvedValue(null);

      await service.pauseQuiz('user-id', 'quiz-id', 'q-id', 0);

      expect(userQuizProgressRepo.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          status: QuizProgressStatus.TIMEOUT,
          remainingTimeSeconds: 0,
        }),
        ['userId', 'quizId'],
      );
    });
  });

  describe('getUserStats', () => {
    it('should return parsed user stats', async () => {
      quizRepo.count.mockResolvedValue(20);
      userQuizProgressRepo.createQueryBuilder().getRawOne.mockResolvedValue({
        passedQuizzes: '5',
        averageScore: '88.50',
        totalScore: '442.50',
      });

      const result = await service.getUserStats('user-id');

      expect(result).toEqual({
        totalQuizzes: 20,
        passedQuizzes: 5,
        averageScore: 88.5,
        totalScore: 442.5,
      });
    });

    it('should return zeros if no passed quizzes', async () => {
      quizRepo.count.mockResolvedValue(10);
      userQuizProgressRepo.createQueryBuilder().getRawOne.mockResolvedValue({
        passedQuizzes: null,
        averageScore: null,
        totalScore: null,
      });

      const result = await service.getUserStats('user-id');
      expect(result.passedQuizzes).toBe(0);
      expect(result.averageScore).toBe(0);
      expect(result.totalScore).toBe(0);
    });
  });
});
