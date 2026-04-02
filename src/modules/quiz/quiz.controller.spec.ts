import { Test, TestingModule } from '@nestjs/testing';
import { QuizController } from './quiz.controller';
import { QuizService } from './quiz.service';

const mockQuizService = {
  getQuizzes: jest.fn(),
  getQuestionsByQuiz: jest.fn(),
  getAnswersByQuestion: jest.fn(),
  getPassedQuizzesNames: jest.fn(),
  getUserQuizAnswer: jest.fn(),
  getQuizProgress: jest.fn(),
  startQuiz: jest.fn(),
  insertUserProgress: jest.fn(),
  pauseQuiz: jest.fn(),
  getActivities: jest.fn(),
  getUserStats: jest.fn(),
  getLeaderboard: jest.fn(),
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

  it('should call startQuiz and return success message', async () => {
    mockQuizService.startQuiz.mockResolvedValue(undefined);
    const result = await controller.startQuiz('user-id', 'quiz-id');
    expect(result).toEqual({ message: 'Quiz started successfully' });
  });

  it('should call pauseQuiz and return success message', async () => {
    mockQuizService.pauseQuiz.mockResolvedValue(undefined);
    const result = await controller.pauseQuiz('user-id', 'quiz-id', {
      pausedAtQuestionId: 'q-id',
      remainingTimeSeconds: 270,
    });
    expect(result).toEqual({ message: 'Quiz paused successfully' });
  });

  it('should call getLeaderboard with page and limit', async () => {
    mockQuizService.getLeaderboard.mockResolvedValue({ data: [], meta: {} });
    await controller.getLeaderboard({ page: 1, limit: 10 });
    expect(mockQuizService.getLeaderboard).toHaveBeenCalledWith(1, 10);
  });

  it('should call getActivities with userId', async () => {
    mockQuizService.getActivities.mockResolvedValue([]);
    await controller.getActivities('user-id');
    expect(mockQuizService.getActivities).toHaveBeenCalledWith('user-id');
  });

  it('should call getPassedQuizzesNames with userId', async () => {
    mockQuizService.getPassedQuizzesNames.mockResolvedValue([]);
    await controller.getPassedQuizzesNames('user-id');
    expect(mockQuizService.getPassedQuizzesNames).toHaveBeenCalledWith(
      'user-id',
    );
  });

  it('should call getUserStats with userId', async () => {
    mockQuizService.getUserStats.mockResolvedValue({});
    await controller.getUserStats('user-id');
    expect(mockQuizService.getUserStats).toHaveBeenCalledWith('user-id');
  });

  it('should call getQuizProgress with userId and quizId', async () => {
    mockQuizService.getQuizProgress.mockResolvedValue(null);
    await controller.getQuizProgress('user-id', 'quiz-id');
    expect(mockQuizService.getQuizProgress).toHaveBeenCalledWith(
      'user-id',
      'quiz-id',
    );
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
});
