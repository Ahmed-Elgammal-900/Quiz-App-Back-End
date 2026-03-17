import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { AuthService } from '../src/modules/auth/auth.service';
import { MailService } from '../src/modules/mail/mail.service';
import { UserService } from 'src/modules/user/user.service';

describe('UserController (e2e)', () => {
  let app: INestApplication;
  let module: TestingModule;
  let cookies: string;

  const TEST_USER = {
    name: 'Test User',
    email: 'new-user-test@email.com',
    password: 'Tyfj8f2@d1hkof',
  };

  const loginAndGetCookies = async (): Promise<string> => {
    const res = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: TEST_USER.email, password: TEST_USER.password });

    expect(res.status).toBe(200);
    const setCookieHeader = res.headers['set-cookie'];
    expect(setCookieHeader).toBeDefined();
    return (
      Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader]
    ).join('; ');
  };

  const registerAndVerify = async (): Promise<void> => {
    const register = await request(app.getHttpServer())
      .post('/auth/signup')
      .send(TEST_USER);

    expect(register.status).toBe(201);

    expect(register.body).toBeDefined();
    expect(register.body.data).toBeDefined();
    expect(register.body.data.userId).toBeDefined();

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

    const userService = module.get(UserService);
    await userService.deleteTestUser(TEST_USER.email);
    await userService.deleteTestDeletedEmail(TEST_USER.email);

    await registerAndVerify();
    cookies = await loginAndGetCookies();
  });

  afterAll(async () => {
    const userService = module.get(UserService);
    await userService.deleteTestUser(TEST_USER.email);
    await userService.deleteTestDeletedEmail(TEST_USER.email);
    await app.close();
  });

  // DELETE /user/delete

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

      const clearedSetCookie = res.headers['set-cookie'];
      expect(clearedSetCookie).toBeDefined();
      const cookieArray = Array.isArray(clearedSetCookie)
        ? clearedSetCookie
        : [clearedSetCookie];

      expect(cookieArray.some((c) => c.includes('access_token=;'))).toBe(true);
      expect(cookieArray.some((c) => c.includes('refresh_token=;'))).toBe(true);

      cookies = clearedSetCookie;
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
