import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { AuthService } from '../src/modules/auth/auth.service';
import { MailService } from '../src/modules/mail/mail.service';
import { UserService } from '../src/modules/user/user.service';
import { Provider } from '../src/modules/user/constants/provider.constant';

describe('UserController (e2e)', () => {
  let app: INestApplication;
  let module: TestingModule;
  let validCookies: string;
  let clearedCookies: string | string[];

  const TEST_USER = {
    name: 'Test User',
    email: 'new-user-test@email.com',
    password: 'Tyfj8f2@d1hkof',
    confirmPassword: 'Tyfj8f2@d1hkof',
  };

  const normalizeCookies = (raw: string | string[]): string =>
    (Array.isArray(raw) ? raw : [raw]).join('; ');

  const loginAndGetCookies = async (): Promise<string> => {
    const res = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: TEST_USER.email, password: TEST_USER.password });

    expect(res.status).toBe(201);
    const setCookieHeader = res.headers['set-cookie'];
    expect(setCookieHeader).toBeDefined();
    return normalizeCookies(setCookieHeader);
  };

  const registerAndVerify = async (): Promise<void> => {
    const register = await request(app.getHttpServer())
      .post('/auth/signup')
      .send(TEST_USER);

    expect(register.status).toBe(201);
    expect(register.body.data?.userId).toBeDefined();

    const authService = module.get(AuthService);
    await authService.forceVerifyUser(register.body.data.userId);
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
    await userService.deleteTestDeletedEmail(TEST_USER.email).catch(() => {});
    await userService.deleteTestUser(TEST_USER.email).catch(() => {}); // active user cleanup

    await registerAndVerify();
    validCookies = await loginAndGetCookies();
  }, 30000);

  afterAll(async () => {
    try {
      const userService = module.get(UserService);
      await userService.deleteTestDeletedEmail(TEST_USER.email);
    } finally {
      await app.close();
    }
  });


  describe('GET /user', () => {
    it('should fail without auth', async () => {
      const res = await request(app.getHttpServer()).get('/user');

      expect(res.status).toBe(401);
    });

    it('should return user profile', async () => {
      const res = await request(app.getHttpServer())
        .get('/user')
        .set('Cookie', validCookies);

      expect(res.status).toBe(200);
      expect(res.body.data).toMatchObject({
        name: TEST_USER.name,
        email: TEST_USER.email,
        providers: [Provider.LOCAL],
      });
    });
  });

  // DELETE /user

  describe('DELETE /user', () => {
    it('should fail without auth', async () => {
      const res = await request(app.getHttpServer()).delete('/user');

      expect(res.status).toBe(401);
    });

    it('should delete account and clear cookies', async () => {
      const res = await request(app.getHttpServer())
        .delete('/user')
        .set('Cookie', validCookies);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveProperty(
        'message',
        'Account deleted successfully',
      );

      const setCookieHeader = res.headers['set-cookie'];
      expect(setCookieHeader).toBeDefined();

      const cookieArray = Array.isArray(setCookieHeader)
        ? setCookieHeader
        : [setCookieHeader];

      expect(cookieArray.some((c) => c.includes('access_token=;'))).toBe(true);
      expect(cookieArray.some((c) => c.includes('refresh_token=;'))).toBe(true);

      // Store separately — don't overwrite validCookies
      clearedCookies = setCookieHeader;
    });

    it('should fail after deletion — token revoked', async () => {
      const res = await request(app.getHttpServer())
        .delete('/user')
        .set('Cookie', normalizeCookies(clearedCookies));

      expect(res.status).toBe(401);
    });

    it('should prevent re-registration with deleted email', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/signup')
        .send(TEST_USER);

      expect(res.status).toBe(409);
      expect(res.body.message).toBe('this account was deleted');
    });

    it('should prevent login with deleted account', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: TEST_USER.email, password: TEST_USER.password });

      expect(res.status).toBe(400);
      expect(res.body.message).toBe('this account was deleted');
    });
  });
});
