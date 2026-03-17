import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { AuthService } from '../src/modules/auth/auth.service';
import { MailService } from '../src/modules/mail/mail.service';

describe('UserController (e2e)', () => {
  let app: INestApplication;
  let module: TestingModule;
  let cookies: string;

  const TEST_USER = {
    name: 'Test User',
    email: 'new-user-delete-test@email.com',
    password: 'Tyfj8f2@d1hjdf',
  };

  const loginAndGetCookies = async (): Promise<string> => {
    const res = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: TEST_USER.email, password: TEST_USER.password });

    const setCookieHeader = res.headers['set-cookie'];
    return (
      Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader]
    ).join('; ');
  };

  const registerAndVerify = async (): Promise<void> => {
    const register = await request(app.getHttpServer())
      .post('/auth/signup')
      .send(TEST_USER);
    console.log(register.body);
    const userId = register.body.data.userId;
    const authService = module.get(AuthService);
    await authService.forceVerifyUser(userId);
  };

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

    // clean up, register and verify fresh user
    const authService = module.get(AuthService);
    await authService.deleteTestUser(TEST_USER.email);
    await authService.deleteTestUser(TEST_USER.email, true);
    await registerAndVerify();

    cookies = await loginAndGetCookies();
  });

  afterAll(async () => {
    await app.close();
  });

  // ─── DELETE /user/delete ──────────────────────────────────────────────────

  describe('DELETE /user/delete', () => {
    it('should fail without auth', async () => {
      const res = await request(app.getHttpServer()).delete('/user/delete');

      expect(res.status).toBe(401);
    });

    it('should delete account and clear cookies', async () => {
      const res = await request(app.getHttpServer())
        .delete('/user/delete')
        .set('Cookie', cookies);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveProperty(
        'message',
        'Account deleted successfully',
      );

      cookies = res.headers['set-cookie'];
      const clearedCookies = res.headers['set-cookie'];
      const cookieArray = Array.isArray(clearedCookies)
        ? clearedCookies
        : [clearedCookies];

      expect(cookieArray.some((c) => c.includes('access_token=;'))).toBe(true);
      expect(cookieArray.some((c) => c.includes('refresh_token=;'))).toBe(true);
    });

    it('should fail after deletion — token revoked', async () => {
      const res = await request(app.getHttpServer())
        .delete('/user/delete')
        .set('Cookie', cookies);

      expect(res.status).toBe(401);
    });

    it('should prevent re-registration with deleted email', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/signup')
        .send(TEST_USER);

      expect(res.status).toBe(409);
    });

    it('should prevent login with deleted account', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: TEST_USER.email, password: TEST_USER.password });

      expect(res.status).toBe(400);
    });
  });
});
