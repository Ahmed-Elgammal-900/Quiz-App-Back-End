import { Test, TestingModule } from '@nestjs/testing';
import { QuizController } from './quiz.controller';
import { QuizService } from './quiz.service';

const mockQuizService = {
  getQuizzes: jest.fn(),
  getActivities: jest.fn(),
  getResult: jest.fn(),
  getUserStats: jest.fn(),
  getTopThree: jest.fn(),
  getUserRank: jest.fn(),
  deleteUserAnswers: jest.fn(),
  getLeaderboard: jest.fn(),
  getPassedQuizzesBadges: jest.fn(),
  getQuizWithQuestions: jest.fn(),
  getQuestionsIds: jest.fn(),
  getQuizUserProgress: jest.fn(),
  startQuiz: jest.fn(),
  insertUserProgress: jest.fn(),
  pauseQuiz: jest.fn(),
};

describe('QuizController', () => {
  let controller: QuizController;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      controllers: [QuizController],
      providers: [{ provide: QuizService, useValue: mockQuizService }],
    }).compile();

    controller = module.get<QuizController>(QuizController);
  });

  it('should call getQuizzes with userId', async () => {
    mockQuizService.getQuizzes.mockResolvedValue([]);
    await controller.getQuizzes('user-id');
    expect(mockQuizService.getQuizzes).toHaveBeenCalledWith('user-id');
  });

  it('should call getActivities with userId', async () => {
    mockQuizService.getActivities.mockResolvedValue([]);
    await controller.getActivities('user-id');
    expect(mockQuizService.getActivities).toHaveBeenCalledWith('user-id');
  });

  it('should call getResult with userId and quizId', async () => {
    mockQuizService.getResult.mockResolvedValue({});
    await controller.getResult('user-id', 'quiz-id');
    expect(mockQuizService.getResult).toHaveBeenCalledWith(
      'user-id',
      'quiz-id',
    );
  });

  it('should call getUserStats with userId', async () => {
    mockQuizService.getUserStats.mockResolvedValue({});
    await controller.getUserStats('user-id');
    expect(mockQuizService.getUserStats).toHaveBeenCalledWith('user-id');
  });

  it('should call getTopThree', async () => {
    mockQuizService.getTopThree.mockResolvedValue([]);
    await controller.getTopThree();
    expect(mockQuizService.getTopThree).toHaveBeenCalled();
  });

  it('should call getUserRank with userId', async () => {
    mockQuizService.getUserRank.mockResolvedValue({});
    await controller.getUserRank('user-id');
    expect(mockQuizService.getUserRank).toHaveBeenCalledWith('user-id');
  });

  it('should call deleteUserAnswers with userId and quizId', async () => {
    mockQuizService.deleteUserAnswers.mockResolvedValue(undefined);
    await controller.deleteUserAnswers('user-id', 'quiz-id');
    expect(mockQuizService.deleteUserAnswers).toHaveBeenCalledWith(
      'user-id',
      'quiz-id',
    );
  });

  it('should call getLeaderboard with page and limit', async () => {
    mockQuizService.getLeaderboard.mockResolvedValue({ data: [], meta: {} });
    await controller.getLeaderboard({ page: 1, limit: 10 });
    expect(mockQuizService.getLeaderboard).toHaveBeenCalledWith(1, 10);
  });

  it('should call getPassedQuizzesBadges with userId', async () => {
    mockQuizService.getPassedQuizzesBadges.mockResolvedValue([]);
    await controller.getPassedQuizzesBadges('user-id');
    expect(mockQuizService.getPassedQuizzesBadges).toHaveBeenCalledWith(
      'user-id',
    );
  });

  it('should call getQuizWithQuestions with quizId, page and limit', async () => {
    mockQuizService.getQuizWithQuestions.mockResolvedValue({
      data: [],
      meta: {},
    });
    await controller.getQuestionsByQuiz('quiz-id', { page: 1, limit: 10 });
    expect(mockQuizService.getQuizWithQuestions).toHaveBeenCalledWith(
      'quiz-id',
      1,
      10,
    );
  });

  it('should call getQuestionsIds with quizId', async () => {
    mockQuizService.getQuestionsIds.mockResolvedValue([]);
    await controller.getQuestionsIds('quiz-id');
    expect(mockQuizService.getQuestionsIds).toHaveBeenCalledWith('quiz-id');
  });

  it('should call getQuizUserProgress with userId, quizId and no limit', async () => {
    mockQuizService.getQuizUserProgress.mockResolvedValue([]);
    await controller.getQuizProgress('user-id', 'quiz-id');
    expect(mockQuizService.getQuizUserProgress).toHaveBeenCalledWith(
      'user-id',
      'quiz-id',
      undefined,
    );
  });

  it('should call getQuizUserProgress with userId, quizId and limit', async () => {
    mockQuizService.getQuizUserProgress.mockResolvedValue([]);
    await controller.getQuizProgress('user-id', 'quiz-id', 5);
    expect(mockQuizService.getQuizUserProgress).toHaveBeenCalledWith(
      'user-id',
      'quiz-id',
      5,
    );
  });

  it('should call startQuiz and return success message', async () => {
    mockQuizService.startQuiz.mockResolvedValue(undefined);
    const result = await controller.startQuiz('user-id', 'quiz-id');
    expect(mockQuizService.startQuiz).toHaveBeenCalledWith(
      'user-id',
      'quiz-id',
    );
    expect(result).toEqual({ message: 'Quiz started successfully' });
  });

  it('should call insertUserProgress with correct args', async () => {
    mockQuizService.insertUserProgress.mockResolvedValue({ score: 100 });
    await controller.insertUserProgress('user-id', 'quiz-id', {
      questionId: 'q-id',
      selectedAnswerId: 'a-id',
    });
    expect(mockQuizService.insertUserProgress).toHaveBeenCalledWith(
      'user-id',
      'quiz-id',
      'q-id',
      'a-id',
    );
  });

  it('should call pauseQuiz and return success message', async () => {
    mockQuizService.pauseQuiz.mockResolvedValue(undefined);
    const result = await controller.pauseQuiz('user-id', 'quiz-id', {
      pausedAtQuestionIndex: 3,
      remainingTimeSeconds: 270,
    });
    expect(mockQuizService.pauseQuiz).toHaveBeenCalledWith(
      'user-id',
      'quiz-id',
      3,
      270,
    );
    expect(result).toEqual({ message: 'Quiz paused successfully' });
  });
});
