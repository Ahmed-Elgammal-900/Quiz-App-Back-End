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

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
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
    app.use(cookieParser()); // 👈 required for cookie auth
    await app.init();

    // 1. Clean up existing test user
    const authService = module.get(AuthService);
    await authService.deleteTestUser('test@email.com');

    // 2. Register
    const register = await request(app.getHttpServer())
      .post('/auth/signup')
      .send({
        name: 'Test',
        email: 'test@email.com',
        password: 'Tyfj8f2@d1hjdf',
      });

    const userId = register.body.data.userId; // 👈 wrapped response

    // 3. Force verify
    await authService.forceVerifyUser(userId);

    // 4. Login
    const login = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'test@email.com', password: 'Tyfj8f2@d1hjdf' });

    // 5. Extract cookies
    const setCookieHeader = login.headers['set-cookie'];
    cookies = (
      Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader]
    ).join('; ');

    // 6. Get quizzes
    const quizzes = await request(app.getHttpServer())
      .get('/quizzes')
      .set('Cookie', cookies);

    quizId = quizzes.body.data.quizInfo?.[0]?.id;
    if (!quizId) {
      throw new Error(
        'Test prerequisite failed: No quizzes found in database. Ensure test data is seeded.',
      );
    }

    // 7. Get questions
    const questions = await request(app.getHttpServer())
      .get(`/quizzes/${quizId}/questions`)
      .set('Cookie', cookies);

    questionId = questions.body.data.data?.[0]?.id;
    if (!questionId) {
      throw new Error(
        'Test prerequisite failed: No questions found for quiz. Ensure test data is seeded.',
      );
    }
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /quizzes — should return quizzes', async () => {
    return request(app.getHttpServer())
      .get('/quizzes')
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(res.body.data).toHaveProperty('quizInfo');
        expect(res.body.data).toHaveProperty('quizzesStatus');
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

  it('GET /quizzes/:quizId/progress — should return progress', async () => {
    return request(app.getHttpServer())
      .get(`/quizzes/${quizId}/progress`)
      .set('Cookie', cookies)
      .expect(200);
  });

  it('POST /quizzes/:quizId/pause — should pause quiz', async () => {
    return request(app.getHttpServer())
      .post(`/quizzes/${quizId}/pause`)
      .set('Cookie', cookies)
      .send({
        pausedAtQuestionId: questionId,
        remainingTimeSeconds: 270,
      })
      .expect(201)
      .expect((res) => {
        expect(res.body.data).toHaveProperty(
          'message',
          'Quiz paused successfully',
        );
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

  it('GET /quizzes/leaderboard — should return leaderboard', async () => {
    return request(app.getHttpServer())
      .get('/quizzes/leaderboard')
      .set('Cookie', cookies)
      .expect(200)
      .expect((res) => {
        expect(res.body.data).toHaveProperty('data');
        expect(res.body.data).toHaveProperty('meta');
      });
  });
});
