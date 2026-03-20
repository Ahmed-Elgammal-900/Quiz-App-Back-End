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
});
