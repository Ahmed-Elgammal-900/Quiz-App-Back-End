import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { AuthService } from '../src/modules/auth/auth.service';
import { MailService } from '../src/modules/mail/mail.service';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let module: TestingModule;
  let cookies: string;
  let userId: string;

  const TEST_USER = {
    name: 'Test User',
    email: 'auth-test@email.com',
    password: 'Tyfj8f2@d1hjdf',
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

    const authService = module.get(AuthService);
    await authService.deleteTestUser(TEST_USER.email);
    await authService.deleteTestUser(TEST_USER.email, true);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /auth/signup', () => {
    it('should register a new user', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/signup')
        .send(TEST_USER);

      expect(res.status).toBe(201);
      expect(res.body.data).toHaveProperty('message', 'signup success');
      expect(res.body.data).toHaveProperty('userId');

      userId = res.body.data.userId;
    });

    it('should fail if email already exists', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/signup')
        .send(TEST_USER);

      expect(res.status).toBe(409);
    });

    it('should fail with invalid email', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/signup')
        .send({ ...TEST_USER, email: 'not-an-email' });

      expect(res.status).toBe(400);
    });

    it('should fail with missing fields', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/signup')
        .send({ email: TEST_USER.email });

      expect(res.status).toBe(400);
    });
  });

  describe('POST /auth/login — unverified', () => {
    it('should return otp required if email not verified', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: TEST_USER.email, password: TEST_USER.password });

      expect(res.status).toBe(201);
      expect(res.body.data.message).toBe('otp verification required');
      expect(res.body.data.isEmailVerified).toBe(false);
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('should fail with wrong password', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: TEST_USER.email, password: 'wrongpassword' });

      expect(res.status).toBe(400);
    });

    it('should fail with non-existent email', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: 'nobody@test.com', password: TEST_USER.password });

      expect(res.status).toBe(400);
    });
  });

  describe('POST /auth/verify-email', () => {
    it('should fail with invalid OTP', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/verify-email')
        .send({ id: userId, otp: '000000' });

      expect(res.status).toBe(400);
    });

    it('should fail with invalid userId', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/verify-email')
        .send({ id: 'invalid-id', otp: '123456' });

      expect(res.status).toBe(400);
    });
  });

  describe('POST /auth/resend-otp', () => {
    it('should fail within 60s cooldown', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/resend-otp')
        .send({ id: userId });

      expect(res.status).toBe(400);
    });

    it('should fail with invalid userId', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/resend-otp')
        .send({ id: '00000000-0000-0000-0000-000000000000' });

      expect(res.status).toBe(404);
    });
  });

  describe('POST /auth/login — verified', () => {
    beforeAll(async () => {
      const authService = module.get(AuthService);
      await authService.forceVerifyUser(userId);
    });

    it('should login and set cookies', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: TEST_USER.email, password: TEST_USER.password });

      expect(res.status).toBe(201);
      expect(res.body.data.message).toBe('login success');
      expect(res.body.data.isEmailVerified).toBe(true);
      expect(res.headers['set-cookie']).toBeDefined();

      const setCookieHeader = res.headers['set-cookie'];
      cookies = (
        Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader]
      ).join('; ');
    });
  });

  describe('POST /auth/refresh-token', () => {
    it('should rotate tokens and set new cookies', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/refresh-token')
        .set('Cookie', cookies);

      expect(res.status).toBe(201);
      expect(res.body.data).toHaveProperty('message', 'success access token');
      expect(res.headers['set-cookie']).toBeDefined();

      const setCookieHeader = res.headers['set-cookie'];
      cookies = (
        Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader]
      ).join('; ');
    });

    it('should fail without cookies', async () => {
      const res = await request(app.getHttpServer()).post(
        '/auth/refresh-token',
      );

      expect(res.status).toBe(401);
    });
  });

  describe('PATCH /auth/change-password', () => {
    it('should fail with wrong current password', async () => {
      const res = await request(app.getHttpServer())
        .patch('/auth/change-password')
        .set('Cookie', cookies)
        .send({
          currentPassword: 'wrongpassword',
          newPassword: 'NewPass123!',
        });

      expect(res.status).toBe(400);
    });

    it('should fail if new password is same as current', async () => {
      const res = await request(app.getHttpServer())
        .patch('/auth/change-password')
        .set('Cookie', cookies)
        .send({
          currentPassword: TEST_USER.password,
          newPassword: TEST_USER.password,
        });

      expect(res.status).toBe(400);
    });

    it('should change password successfully', async () => {
      const res = await request(app.getHttpServer())
        .patch('/auth/change-password')
        .set('Cookie', cookies)
        .send({
          currentPassword: TEST_USER.password,
          newPassword: 'NewPass123!@#',
          confirmPassword: 'NewPass123!@#',
        });

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveProperty(
        'message',
        'password changed successfully',
      );
    });

    it('should fail without auth', async () => {
      const res = await request(app.getHttpServer())
        .patch('/auth/change-password')
        .send({
          currentPassword: TEST_USER.password,
          newPassword: 'NewPass123!@#',
        });

      expect(res.status).toBe(401);
    });
  });

  describe('POST /auth/forget-password', () => {
    it('should return same message whether email exists or not', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/forget-password')
        .send({ email: TEST_USER.email });

      expect(res.status).toBe(201);
      expect(res.body.data).toHaveProperty(
        'message',
        'If email exists, reset link has been sent',
      );
    });

    it('should return same message for non-existent email', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/forget-password')
        .send({ email: 'nobody@test.com' });

      expect(res.status).toBe(201);
      expect(res.body.data).toHaveProperty(
        'message',
        'If email exists, reset link has been sent',
      );
    });

    it('should fail with invalid email format', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/forget-password')
        .send({ email: 'not-an-email' });

      expect(res.status).toBe(400);
    });
  });

  describe('POST /auth/logout', () => {
    it('should fail without auth', async () => {
      const res = await request(app.getHttpServer()).post('/auth/logout');

      expect(res.status).toBe(401);
    });

    it('should logout and clear cookies', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Cookie', cookies);

      expect(res.status).toBe(201);
      expect(res.body.data).toHaveProperty('message', 'logout success');

      cookies = res.headers['set-cookie'];
      const clearedCookies = res.headers['set-cookie'];
      const cookieArray = Array.isArray(clearedCookies)
        ? clearedCookies
        : [clearedCookies];
      expect(cookieArray.some((c) => c.includes('access_token=;'))).toBe(true);
      expect(cookieArray.some((c) => c.includes('refresh_token=;'))).toBe(true);
    });

    it('should fail after logout', async () => {
      const res = await request(app.getHttpServer())
        .patch('/auth/change-password')
        .set('Cookie', cookies)
        .send({
          currentPassword: 'NewPass123!@#',
          newPassword: 'AnotherPass123!',
          confirmPassword: 'AnotherPass123!',
        });

      expect(res.status).toBe(401);
    });
  });
});
