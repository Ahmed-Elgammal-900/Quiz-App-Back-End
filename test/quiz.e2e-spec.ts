import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { AuthService } from '../src/modules/auth/auth.service';
import { MailService } from '../src/modules/mail/mail.service';

describe('QuizController (e2e)', () => {
  let app: INestApplication;
  let cookies: string;
  let quizId: string;
  let questionId: string;
  let answerId: string;
  let module: TestingModule;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(MailService)
      .useValue({
        sendVerificationEmail: jest.fn(),
        sendPasswordResetEmail: jest.fn(),
        sendOtpEmail: jest.fn(),
        sendResetPasswordEmail: jest.fn(),
      })
      .compile();

    app = module.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true }));
    app.use(cookieParser());
    await app.init();

    const register = await request(app.getHttpServer())
      .post('/auth/signup')
      .send({
        name: 'Test',
        email: 'test@email.com',
        password: 'Tyfj8f2@d1hjdf',
        confirmPassword: 'Tyfj8f2@d1hjdf',
      });

    const userId = register.body.data.userId;

    const authService = module.get(AuthService);
    await authService.forceVerifyUser(userId);

    const login = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'test@email.com', password: 'Tyfj8f2@d1hjdf' });

    const setCookieHeader = login.headers['set-cookie'];
    cookies = (
      Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader]
    ).join('; ');

    const quizzes = await request(app.getHttpServer())
      .get('/quizzes')
      .set('Cookie', cookies);

    quizId = quizzes.body.data?.[0]?.id;
    if (!quizId) {
      throw new Error(
        'Test prerequisite failed: No quizzes found in database. Ensure test data is seeded.',
      );
    }

    const questions = await request(app.getHttpServer())
      .get(`/quizzes/${quizId}/questions`)
      .set('Cookie', cookies);

    questionId = questions.body.data.questions?.[0]?.id;
    if (!questionId) {
      throw new Error(
        'Test prerequisite failed: No questions found for quiz. Ensure test data is seeded.',
      );
    }

    answerId = questions.body.data.questions?.[0]?.answers?.[0]?.id;
    if (!answerId) {
      throw new Error(
        'Test prerequisite failed: No answers found for first question. Ensure test data is seeded.',
      );
    }
  });

  afterAll(async () => {
    const authService = module.get(AuthService);
    await authService.deleteTestUser('test@email.com');
    await app.close();
  });

  it('GET /quizzes — should return 401 without cookie', async () => {
    return request(app.getHttpServer()).get('/quizzes').expect(401);
  });

  it('GET /quizzes/:quizId/questions — should return 400 for invalid UUID', async () => {
    return request(app.getHttpServer())
      .get('/quizzes/not-a-uuid/questions')
      .set('Cookie', cookies)
      .expect(400);
  });

  it('GET /quizzes — should return flat array of quizzes', async () => {
    return request(app.getHttpServer())
      .get('/quizzes')
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(Array.isArray(res.body.data)).toBe(true);
        expect(res.body.data[0]).toHaveProperty('id');
        expect(res.body.data[0]).toHaveProperty('title');
      });
  });

  it('GET /quizzes/top-three — should return up to 3 users', async () => {
    return request(app.getHttpServer())
      .get('/quizzes/top-three')
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(Array.isArray(res.body.data)).toBe(true);
        expect(res.body.data.length).toBeLessThanOrEqual(3);
      });
  });

  it('GET /quizzes/my-rank — should return rank and stats', async () => {
    return request(app.getHttpServer())
      .get('/quizzes/my-rank')
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(res.body.data).toHaveProperty('rank');
        expect(res.body.data).toHaveProperty('totalScore');
        expect(res.body.data).toHaveProperty('name');
      });
  });

  it('GET /quizzes/stats — should return user stats', async () => {
    return request(app.getHttpServer())
      .get('/quizzes/stats')
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(res.body.data).toHaveProperty('totalQuizzes');
        expect(res.body.data).toHaveProperty('passedQuizzes');
        expect(res.body.data).toHaveProperty('averageScore');
        expect(res.body.data).toHaveProperty('totalScore');
      });
  });

  it('GET /quizzes/leaderboard — should return paginated leaderboard', async () => {
    return request(app.getHttpServer())
      .get('/quizzes/leaderboard')
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(res.body.data).toHaveProperty('data');
        expect(res.body.data).toHaveProperty('meta');
        expect(res.body.data.meta).toHaveProperty('page');
        expect(res.body.data.meta).toHaveProperty('limit');
        expect(res.body.data.meta).toHaveProperty('totalPages');
      });
  });

  it('GET /quizzes/earned-badges — should return passed quiz badges', async () => {
    return request(app.getHttpServer())
      .get('/quizzes/earned-badges')
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(Array.isArray(res.body.data)).toBe(true);
        if (res.body.data.length > 0) {
          expect(res.body.data[0]).toEqual(
            expect.objectContaining({
              quizId: expect.any(String),
              badgeTitle: expect.any(String),
            }),
          );
        }
      });
  });

  it('GET /quizzes/:quizId/questions — should return paginated questions with answers', async () => {
    return request(app.getHttpServer())
      .get(`/quizzes/${quizId}/questions`)
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(res.body.data).toHaveProperty('quizTitle');
        expect(res.body.data).toHaveProperty('questions');
        expect(res.body.data).toHaveProperty('pagination');
        expect(Array.isArray(res.body.data.questions)).toBe(true);
      });
  });

  it('GET /quizzes/:quizId/questions/ids — should return array of question UUIDs', async () => {
    return request(app.getHttpServer())
      .get(`/quizzes/${quizId}/questions/ids`)
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(Array.isArray(res.body.data)).toBe(true);
        expect(typeof res.body.data[0]).toBe('string');
      });
  });

  it('POST /quizzes/:quizId/start — should start quiz', async () => {
    return request(app.getHttpServer())
      .post(`/quizzes/${quizId}/start`)
      .set('Cookie', cookies)
      .expect(201)
      .expect((res) => {
        expect(res.body.data).toHaveProperty(
          'message',
          'Quiz started successfully',
        );
      });
  });

  it('GET /quizzes/:quizId/progress — should return progress after start', async () => {
    return request(app.getHttpServer())
      .get(`/quizzes/${quizId}/progress`)
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(res.body.data).toHaveProperty('pausedAt');
        expect(res.body.data).toHaveProperty('answers');
        expect(res.body.data).toHaveProperty('currentPage');
      });
  });

  it('POST /quizzes/:quizId/progress — should save answer and return score', async () => {
    return request(app.getHttpServer())
      .post(`/quizzes/${quizId}/progress`)
      .set('Cookie', cookies)
      .send({ questionId, selectedAnswerId: answerId })
      .expect(201)
      .expect((res) => {
        expect(res.body.data).toHaveProperty('score');
        expect(res.body.data).toHaveProperty('passed');
        expect(res.body.data).toHaveProperty('isLastQuestion');
        expect(res.body.data).toHaveProperty('answerIsCorrect');
      });
  });

  it('POST /quizzes/:quizId/pause — should pause quiz', async () => {
    await request(app.getHttpServer())
      .post(`/quizzes/${quizId}/start`)
      .set('Cookie', cookies);

    return request(app.getHttpServer())
      .post(`/quizzes/${quizId}/pause`)
      .set('Cookie', cookies)
      .send({ pausedAtQuestionIndex: 0, remainingTimeSeconds: 270 })
      .expect(201)
      .expect((res) => {
        expect(res.body.data).toHaveProperty(
          'message',
          'Quiz paused successfully',
        );
      });
  });

  it('GET /quizzes/activities — should return active activities', async () => {
    return request(app.getHttpServer())
      .get('/quizzes/activities')
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(Array.isArray(res.body.data)).toBe(true);
        if (res.body.data.length > 0) {
          expect(res.body.data[0]).toEqual(
            expect.objectContaining({
              id: expect.any(String),
              status: expect.any(String),
              passed: expect.any(Boolean),
              quiz: expect.objectContaining({ title: expect.any(String) }),
            }),
          );
        }
      });
  });

  it('DELETE /quizzes/:quizId/delete-user-answers — should delete answers after failed attempt', async () => {
    await request(app.getHttpServer())
      .post(`/quizzes/${quizId}/start`)
      .set('Cookie', cookies);

    await request(app.getHttpServer())
      .post(`/quizzes/${quizId}/pause`)
      .set('Cookie', cookies)
      .send({ pausedAtQuestionIndex: 0, remainingTimeSeconds: 0 });

    return request(app.getHttpServer())
      .delete(`/quizzes/${quizId}/delete-user-answers`)
      .set('Cookie', cookies)
      .expect(200);
  });

  it('GET /quizzes/:quizId/get-result — should return result after attempt', async () => {
    return request(app.getHttpServer())
      .get(`/quizzes/${quizId}/get-result`)
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(res.body.data).toHaveProperty('quizTitle');
        expect(res.body.data).toHaveProperty('score');
        expect(res.body.data).toHaveProperty('passed');
        expect(res.body.data).toHaveProperty('correctAnswers');
        expect(res.body.data).toHaveProperty('totalQuestions');
        expect(res.body.data).toHaveProperty('timeTaken');
      });
  });
});
