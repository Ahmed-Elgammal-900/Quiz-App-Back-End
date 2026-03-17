// src/modules/auth/auth.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { MailService } from '../mail/mail.service';
import { UserService } from '../user/user.service';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';

jest.mock('bcrypt');

const mockUserService = {
  createUser: jest.fn(),
  findOne: jest.fn(),
  findDeletedByEmail: jest.fn(),
  findOrCreateGoogleUser: jest.fn(),
  updateUser: jest.fn(),
  saveToken: jest.fn(),
  getToken: jest.fn(),
  clearToken: jest.fn(),
  verifyUser: jest.fn(),
  incrementAttempts: jest.fn(),
  deleteTestUser: jest.fn(),
};

const mockMailService = {
  sendOtpEmail: jest.fn(),
  sendResetPasswordEmail: jest.fn(),
};

const mockJwtService = {
  sign: jest.fn().mockReturnValue('mock-token'),
};

const mockConfigService = {
  get: jest.fn().mockReturnValue('test-secret'),
};

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: MailService, useValue: mockMailService },
        { provide: UserService, useValue: mockUserService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    jest.clearAllMocks();
  });

  // ─── createUser ───────────────────────────────────────────────────────────

  describe('createUser', () => {
    it('should create user and send OTP', async () => {
      const user = { id: 'user-123', email: 'test@test.com', name: 'Test' };
      mockUserService.createUser.mockResolvedValue(user);
      mockUserService.getToken.mockResolvedValue(null);
      mockUserService.saveToken.mockResolvedValue(undefined);
      mockMailService.sendOtpEmail.mockResolvedValue(undefined);

      const result = await service.createUser({
        name: 'Test',
        email: 'test@test.com',
        password: 'Pass123!',
      });

      expect(result).toEqual(user);
      expect(mockUserService.createUser).toHaveBeenCalledTimes(1);
      expect(mockMailService.sendOtpEmail).toHaveBeenCalledTimes(1);
    });
  });

  // ─── validateLocalUser ────────────────────────────────────────────────────

  describe('validateLocalUser', () => {
    it('should return user on valid credentials', async () => {
      const user = {
        id: 'user-123',
        email: 'test@test.com',
        password: 'hashed',
        isEmailVerified: true,
      };
      mockUserService.findDeletedByEmail.mockResolvedValue(null);
      mockUserService.findOne.mockResolvedValue(user);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const result = await service.validateLocalUser({
        email: 'test@test.com',
        password: 'Pass123!',
      });

      expect(result).toEqual(user);
    });

    it('should throw if account was deleted', async () => {
      mockUserService.findDeletedByEmail.mockResolvedValue({ id: 'deleted' });

      await expect(
        service.validateLocalUser({
          email: 'test@test.com',
          password: 'Pass123!',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw if user not found', async () => {
      mockUserService.findDeletedByEmail.mockResolvedValue(null);
      mockUserService.findOne.mockResolvedValue(null);

      await expect(
        service.validateLocalUser({
          email: 'test@test.com',
          password: 'Pass123!',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw if password is incorrect', async () => {
      mockUserService.findDeletedByEmail.mockResolvedValue(null);
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        password: 'hashed',
        isEmailVerified: true,
      });
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(
        service.validateLocalUser({
          email: 'test@test.com',
          password: 'wrong',
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  // ─── validateGoogleUser ───────────────────────────────────────────────────

  describe('validateGoogleUser', () => {
    it('should return user info for valid google user', async () => {
      const user = {
        id: 'user-123',
        email: 'test@test.com',
        isEmailVerified: true,
        name: 'Test',
      };
      mockUserService.findDeletedByEmail.mockResolvedValue(null);
      mockUserService.findOrCreateGoogleUser.mockResolvedValue(user);

      const result = await service.validateGoogleUser({
        email: 'test@test.com',
        name: 'Test',
        googleId: 'google-123',
      });

      expect(result).toEqual({
        id: user.id,
        email: user.email,
        isEmailVerified: user.isEmailVerified,
      });
    });

    it('should throw if account was deleted', async () => {
      mockUserService.findDeletedByEmail.mockResolvedValue({ id: 'deleted' });

      await expect(
        service.validateGoogleUser({
          email: 'test@test.com',
          name: 'Test',
          googleId: 'google-123',
        }),
      ).rejects.toThrow(ConflictException);
    });
  });

  // ─── verifyOtp ────────────────────────────────────────────────────────────

  describe('verifyOtp', () => {
    it('should verify OTP and return user', async () => {
      const otpToken = {
        token: 'hashed-otp',
        attempts: 0,
        expiresAt: new Date(Date.now() + 60000),
      };
      const user = {
        id: 'user-123',
        email: 'test@test.com',
        isEmailVerified: true,
      };
      mockUserService.getToken.mockResolvedValue(otpToken);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);
      mockUserService.verifyUser.mockResolvedValue(undefined);
      mockUserService.findOne.mockResolvedValue(user);

      const result = await service.verifyOtp('user-123', '123456');

      expect(result).toEqual({
        id: user.id,
        email: user.email,
        isEmailVerified: user.isEmailVerified,
      });
    });

    it('should throw if no OTP found', async () => {
      mockUserService.getToken.mockResolvedValue(null);

      await expect(service.verifyOtp('user-123', '123456')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw if max attempts exceeded', async () => {
      mockUserService.getToken.mockResolvedValue({ attempts: 5 });

      await expect(service.verifyOtp('user-123', '123456')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw if OTP expired', async () => {
      mockUserService.getToken.mockResolvedValue({
        attempts: 0,
        expiresAt: new Date(Date.now() - 1000),
      });

      await expect(service.verifyOtp('user-123', '123456')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw if OTP is invalid', async () => {
      mockUserService.getToken.mockResolvedValue({
        attempts: 0,
        expiresAt: new Date(Date.now() + 60000),
        token: 'hashed',
      });
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(service.verifyOtp('user-123', 'wrong')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  // ─── resendOtp ────────────────────────────────────────────────────────────

  describe('resendOtp', () => {
    it('should resend OTP for unverified user', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        email: 'test@test.com',
        name: 'Test',
        isEmailVerified: false,
      });
      mockUserService.getToken.mockResolvedValue(null);
      mockUserService.saveToken.mockResolvedValue(undefined);
      mockMailService.sendOtpEmail.mockResolvedValue(undefined);

      const result = await service.resendOtp('user-123');
      expect(result).toEqual({ message: 'OTP sent successfully' });
    });

    it('should throw if email already verified', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        isEmailVerified: true,
      });

      await expect(service.resendOtp('user-123')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw if user not found', async () => {
      mockUserService.findOne.mockResolvedValue(null);

      await expect(service.resendOtp('user-123')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  // ─── changePassword ───────────────────────────────────────────────────────

  describe('changePassword', () => {
    it('should change password successfully', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        password: 'hashed',
      });
      (bcrypt.compare as jest.Mock)
        .mockResolvedValueOnce(true) // current password matches
        .mockResolvedValueOnce(false); // new password is different
      (bcrypt.hash as jest.Mock).mockResolvedValue('new-hashed');

      await service.changePassword('user-123', {
        currentPassword: 'old',
        newPassword: 'new',
        confirmPassword: 'new',
      });

      expect(mockUserService.updateUser).toHaveBeenCalledWith('user-123', {
        password: 'new-hashed',
      });
    });

    it('should throw if current password is wrong', async () => {
      mockUserService.findOne.mockResolvedValue({ password: 'hashed' });
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(
        service.changePassword('user-123', {
          currentPassword: 'wrong',
          newPassword: 'new',
          confirmPassword: 'new',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw if new password is same as old', async () => {
      mockUserService.findOne.mockResolvedValue({ password: 'hashed' });
      (bcrypt.compare as jest.Mock)
        .mockResolvedValueOnce(true) // current matches
        .mockResolvedValueOnce(true); // new is same

      await expect(
        service.changePassword('user-123', {
          currentPassword: 'same',
          newPassword: 'same',
          confirmPassword: 'same',
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  // ─── logout ───────────────────────────────────────────────────────────────

  describe('logout', () => {
    it('should logout user and clear refresh token', async () => {
      mockUserService.findOne.mockResolvedValue({ id: 'user-123' });
      mockUserService.clearToken.mockResolvedValue(undefined);

      await service.logout('user-123');

      expect(mockUserService.clearToken).toHaveBeenCalledTimes(1);
    });

    it('should throw if user not found', async () => {
      mockUserService.findOne.mockResolvedValue(null);

      await expect(service.logout('user-123')).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  // ─── forceVerifyUser ──────────────────────────────────────────────────────

  describe('forceVerifyUser', () => {
    it('should force verify user in test environment', async () => {
      process.env.NODE_ENV = 'test';
      mockUserService.updateUser.mockResolvedValue(undefined);

      await service.forceVerifyUser('user-123');

      expect(mockUserService.updateUser).toHaveBeenCalledWith('user-123', {
        isEmailVerified: true,
      });
    });

    it('should throw in non-test environment', async () => {
      process.env.NODE_ENV = 'production';

      await expect(service.forceVerifyUser('user-123')).rejects.toThrow(
        ForbiddenException,
      );

      process.env.NODE_ENV = 'test';
    });
  });

  // ─── deleteTestUser ───────────────────────────────────────────────────────

  describe('deleteTestUser', () => {
    it('should delete user in test environment', async () => {
      process.env.NODE_ENV = 'test';
      mockUserService.deleteTestUser.mockResolvedValue(undefined);

      await service.deleteTestUser('test@test.com');

      expect(mockUserService.deleteTestUser).toHaveBeenCalledWith(
        'test@test.com',
      );
    });

    it('should throw in non-test environment', async () => {
      process.env.NODE_ENV = 'production';

      await expect(service.deleteTestUser('test@test.com')).rejects.toThrow(
        ForbiddenException,
      );

      process.env.NODE_ENV = 'test';
    });
  });

  // ─── generateTokens ───────────────────────────────────────────────────────

  describe('generateTokens', () => {
    it('should generate access and refresh tokens', async () => {
      mockUserService.saveToken.mockResolvedValue(undefined);

      const result = await service.generateTokens({
        id: 'user-123',
        email: 'test@test.com',
        isEmailVerified: true,
      });

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(mockJwtService.sign).toHaveBeenCalledTimes(2);
    });
  });

  // ─── forgotPassword ───────────────────────────────────────────────────────

  describe('forgotPassword', () => {
    it('should return generic message if user not found', async () => {
      mockUserService.findOne.mockResolvedValue(null);

      const result = await service.forgotPassword('notfound@test.com');

      expect(result).toEqual({
        message: 'If email exists, reset link has been sent',
      });
      expect(mockMailService.sendResetPasswordEmail).not.toHaveBeenCalled();
    });

    it('should send reset email if user exists', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        email: 'test@test.com',
        name: 'Test',
      });
      mockUserService.saveToken.mockResolvedValue(undefined);
      mockMailService.sendResetPasswordEmail.mockResolvedValue(undefined);

      const result = await service.forgotPassword('test@test.com');

      expect(result).toEqual({
        message: 'If email exists, reset link has been sent',
      });
      expect(mockMailService.sendResetPasswordEmail).toHaveBeenCalledTimes(1);
    });
  });
});
