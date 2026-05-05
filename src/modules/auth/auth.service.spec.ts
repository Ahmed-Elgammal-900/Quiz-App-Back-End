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
import { TokenType } from './constants/token-type.constant';
import { Provider } from '../user/constants/provider.constant';

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
  deleteTestDeletedEmail: jest.fn(),
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
        confirmPassword: 'Pass123!',
      });

      expect(result).toEqual(user);
      expect(mockUserService.createUser).toHaveBeenCalledTimes(1);
      expect(mockMailService.sendOtpEmail).toHaveBeenCalledTimes(1);
    });
  });

  describe('validateLocalUser', () => {
    it('should return user on valid credentials with verified email', async () => {
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
      expect(mockMailService.sendOtpEmail).not.toHaveBeenCalled();
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

    it('should send OTP and not throw if email not verified', async () => {
      mockUserService.findDeletedByEmail.mockResolvedValue(null);
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        email: 'test@test.com',
        name: 'Test',
        password: 'hashed',
        isEmailVerified: false,
      });
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);
      mockUserService.getToken.mockResolvedValue({
        lastSentAt: new Date(Date.now() - 30000),
      });

      const result = await service.validateLocalUser({
        email: 'test@test.com',
        password: 'Pass123!',
      });

      expect(mockMailService.sendOtpEmail).not.toHaveBeenCalled();
      expect(result).toBeDefined();
    });
  });

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

    it('should throw ConflictException if account was deleted', async () => {
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

  describe('generateOAuthCode', () => {
    it('should generate and store a hashed OAuth code', async () => {
      mockUserService.saveToken.mockResolvedValue(undefined);

      const result = await service.generateOAuthCode('user-123');

      expect(typeof result).toBe('string');
      expect(result).toHaveLength(64);
      expect(mockUserService.saveToken).toHaveBeenCalledWith(
        'user-123',
        expect.any(String),
        TokenType.OAUTH_CODE,
        expect.any(Date),
      );
    });

    it('should store a hash of the code, not the raw code', async () => {
      mockUserService.saveToken.mockResolvedValue(undefined);

      const code = await service.generateOAuthCode('user-123');
      const storedHash = mockUserService.saveToken.mock.calls[0][1];

      expect(storedHash).not.toBe(code);
      expect(storedHash).toHaveLength(64);
    });

    it('should generate unique codes on each call', async () => {
      mockUserService.saveToken.mockResolvedValue(undefined);

      const code1 = await service.generateOAuthCode('user-123');
      const code2 = await service.generateOAuthCode('user-123');

      expect(code1).not.toBe(code2);
    });

    it('should set expiry ~60 seconds in the future', async () => {
      mockUserService.saveToken.mockResolvedValue(undefined);

      const before = Date.now();
      await service.generateOAuthCode('user-123');
      const after = Date.now();

      const expiresAt: Date = mockUserService.saveToken.mock.calls[0][3];
      expect(expiresAt.getTime()).toBeGreaterThanOrEqual(before + 59000);
      expect(expiresAt.getTime()).toBeLessThanOrEqual(after + 61000);
    });
  });

  describe('consumeOAuthCode', () => {
    it('should return user info on valid code', async () => {
      const user = {
        id: 'user-123',
        email: 'test@test.com',
        isEmailVerified: true,
      };
      mockUserService.getToken.mockResolvedValue({
        expiresAt: new Date(Date.now() + 60000),
        userId: 'user-123',
      });
      mockUserService.clearToken.mockResolvedValue(undefined);
      mockUserService.findOne.mockResolvedValue(user);

      const result = await service.consumeOAuthCode('valid-code');

      expect(result).toEqual({
        id: user.id,
        email: user.email,
        isEmailVerified: user.isEmailVerified,
      });
      expect(mockUserService.clearToken).toHaveBeenCalledWith(
        TokenType.OAUTH_CODE,
        'user-123',
      );
    });

    it('should throw UnauthorizedException if token not found', async () => {
      mockUserService.getToken.mockResolvedValue(null);

      await expect(service.consumeOAuthCode('invalid-code')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException and clear token if expired', async () => {
      mockUserService.getToken.mockResolvedValue({
        expiresAt: new Date(Date.now() - 1000),
        userId: 'user-123',
      });
      mockUserService.clearToken.mockResolvedValue(undefined);

      await expect(service.consumeOAuthCode('expired-code')).rejects.toThrow(
        UnauthorizedException,
      );

      expect(mockUserService.clearToken).toHaveBeenCalledWith(
        TokenType.OAUTH_CODE,
        'user-123',
      );
    });

    it('should throw NotFoundException if user not found after clearing token', async () => {
      mockUserService.getToken.mockResolvedValue({
        expiresAt: new Date(Date.now() + 60000),
        userId: 'user-123',
      });
      mockUserService.clearToken.mockResolvedValue(undefined);
      mockUserService.findOne.mockResolvedValue(null);

      await expect(service.consumeOAuthCode('valid-code')).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should hash the code before querying the token store', async () => {
      mockUserService.getToken.mockResolvedValue({
        expiresAt: new Date(Date.now() + 60000),
        userId: 'user-123',
      });
      mockUserService.clearToken.mockResolvedValue(undefined);
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        email: 'test@test.com',
        isEmailVerified: true,
      });

      await service.consumeOAuthCode('plain-code');

      const calledWithHash = mockUserService.getToken.mock.calls[0][2];
      expect(calledWithHash).not.toBe('plain-code');
      expect(calledWithHash).toHaveLength(64);
    });
  });

  describe('sendOtp', () => {
    it('should send OTP and return success message', async () => {
      mockUserService.getToken.mockResolvedValue(null);
      mockUserService.saveToken.mockResolvedValue(undefined);
      mockMailService.sendOtpEmail.mockResolvedValue(undefined);

      const result = await service.sendOtp('user-123', 'test@test.com', 'Test');

      expect(result).toEqual({ message: 'OTP sent successfully' });
      expect(mockMailService.sendOtpEmail).toHaveBeenCalledTimes(1);
    });

    it('should throw BadRequestException if called within 60s cooldown', async () => {
      mockUserService.getToken.mockResolvedValue({
        lastSentAt: new Date(Date.now() - 30000),
      });

      await expect(
        service.sendOtp('user-123', 'test@test.com'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should skip cooldown and return early if isFromLogin=true', async () => {
      mockUserService.getToken.mockResolvedValue({
        lastSentAt: new Date(Date.now() - 30000),
      });

      const result = await service.sendOtp(
        'user-123',
        'test@test.com',
        'Test',
        true,
      );

      expect(result).toEqual({ message: 'OTP already sent' });
      expect(mockMailService.sendOtpEmail).not.toHaveBeenCalled();
    });

    it('should clear token and rethrow if mail fails', async () => {
      mockUserService.getToken.mockResolvedValue(null);
      mockUserService.saveToken.mockResolvedValue(undefined);
      mockMailService.sendOtpEmail.mockRejectedValue(new Error('SMTP error'));

      await expect(
        service.sendOtp('user-123', 'test@test.com'),
      ).rejects.toThrow('SMTP error');

      expect(mockUserService.clearToken).toHaveBeenCalledWith(
        TokenType.EMAIL_VERIFY,
        'user-123',
      );
    });
  });

  describe('verifyOtp', () => {
    it('should verify OTP and return user', async () => {
      const user = {
        id: 'user-123',
        email: 'test@test.com',
        isEmailVerified: true,
      };
      mockUserService.getToken.mockResolvedValue({
        token: 'hashed-otp',
        attempts: 0,
        expiresAt: new Date(Date.now() + 60000),
      });
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

    it('should throw and increment attempts if OTP is invalid', async () => {
      mockUserService.getToken.mockResolvedValue({
        attempts: 0,
        expiresAt: new Date(Date.now() + 60000),
        token: 'hashed',
      });
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(service.verifyOtp('user-123', 'wrong')).rejects.toThrow(
        BadRequestException,
      );

      expect(mockUserService.incrementAttempts).toHaveBeenCalledWith(
        'user-123',
      );
    });
  });

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

    it('should throw BadRequestException if email already verified', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        isEmailVerified: true,
      });

      await expect(service.resendOtp('user-123')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw NotFoundException if user not found', async () => {
      mockUserService.findOne.mockResolvedValue(null);

      await expect(service.resendOtp('user-123')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('changePassword', () => {
    it('should change password for LOCAL-only provider', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        password: 'hashed',
        providers: [Provider.LOCAL],
      });
      (bcrypt.compare as jest.Mock)
        .mockResolvedValueOnce(true) // currentPassword matches
        .mockResolvedValueOnce(false); // newPassword is different
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

    it('should throw NotFoundException if user not found', async () => {
      mockUserService.findOne.mockResolvedValue(null);

      await expect(
        service.changePassword('user-123', {
          newPassword: 'new',
          confirmPassword: 'new',
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw if currentPassword missing for LOCAL-only provider', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        password: 'hashed',
        providers: [Provider.LOCAL],
      });

      await expect(
        service.changePassword('user-123', {
          newPassword: 'new',
          confirmPassword: 'new',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw if current password is wrong for LOCAL-only provider', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        password: 'hashed',
        providers: [Provider.LOCAL],
      });
      (bcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

      await expect(
        service.changePassword('user-123', {
          currentPassword: 'wrong',
          newPassword: 'new',
          confirmPassword: 'new',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw if new password is same as current for LOCAL-only provider', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        password: 'hashed',
        providers: [Provider.LOCAL],
      });
      (bcrypt.compare as jest.Mock)
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(true);

      await expect(
        service.changePassword('user-123', {
          currentPassword: 'same',
          newPassword: 'same',
          confirmPassword: 'same',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should change password without currentPassword for OAuth-only provider', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        password: null,
        providers: [Provider.GOOGLE],
      });

      (bcrypt.compare as jest.Mock)
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false);
      (bcrypt.hash as jest.Mock).mockResolvedValue('new-hashed');

      await service.changePassword('user-123', {
        newPassword: 'new',
        confirmPassword: 'new',
      });

      expect(mockUserService.updateUser).toHaveBeenCalledWith('user-123', {
        password: 'new-hashed',
      });
      expect(bcrypt.compare).not.toHaveBeenCalled();
    });

    it('should change password without currentPassword for mixed LOCAL+GOOGLE provider', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        password: 'hashed',
        providers: [Provider.LOCAL, Provider.GOOGLE],
      });
      (bcrypt.hash as jest.Mock).mockResolvedValue('new-hashed');

      await service.changePassword('user-123', {
        currentPassword: 'hashed',
        newPassword: 'new',
        confirmPassword: 'new',
      });

      expect(mockUserService.updateUser).toHaveBeenCalledWith('user-123', {
        password: 'new-hashed',
      });
      expect(bcrypt.compare).toHaveBeenCalled();
    });
  });

  describe('resetPassword', () => {
    it('should reset password successfully', async () => {
      mockUserService.getToken.mockResolvedValue({
        expiresAt: new Date(Date.now() + 60000),
        userId: 'user-123',
      });
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        email: 'test@test.com',
        isEmailVerified: true,
        providers: [Provider.LOCAL],
      });
      (bcrypt.hash as jest.Mock).mockResolvedValue('new-hashed');
      mockUserService.updateUser.mockResolvedValue(undefined);
      mockUserService.clearToken.mockResolvedValue(undefined);

      const result = await service.resetPassword('newPass123!', 'raw-token');

      expect(mockUserService.updateUser).toHaveBeenCalledWith('user-123', {
        password: 'new-hashed',
      });
      expect(result).toMatchObject({ id: 'user-123' });
    });

    it('should throw BadRequestException if token not found', async () => {
      mockUserService.getToken.mockResolvedValue(null);

      await expect(
        service.resetPassword('newPass123!', 'bad-token'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException and clear token if expired', async () => {
      mockUserService.getToken.mockResolvedValue({
        expiresAt: new Date(Date.now() - 1000),
        userId: 'user-123',
      });
      mockUserService.clearToken.mockResolvedValue(undefined);

      await expect(
        service.resetPassword('newPass123!', 'expired-token'),
      ).rejects.toThrow(BadRequestException);

      expect(mockUserService.clearToken).toHaveBeenCalledWith(
        TokenType.PASSWORD_RESET,
        'user-123',
      );
    });

    it('should throw NotFoundException if user not found', async () => {
      mockUserService.getToken.mockResolvedValue({
        expiresAt: new Date(Date.now() + 60000),
        userId: 'user-123',
      });
      (bcrypt.hash as jest.Mock).mockResolvedValue('new-hashed');
      mockUserService.updateUser.mockResolvedValue(undefined);
      mockUserService.clearToken.mockResolvedValue(undefined);
      mockUserService.findOne.mockResolvedValue(null);

      await expect(
        service.resetPassword('newPass123!', 'valid-token'),
      ).rejects.toThrow(NotFoundException);
    });

    it('should add LOCAL to providers for OAuth-only user after reset', async () => {
      mockUserService.getToken.mockResolvedValue({
        expiresAt: new Date(Date.now() + 60000),
        userId: 'user-123',
      });
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        email: 'test@test.com',
        name: 'Test',
        isEmailVerified: true,
        providers: [Provider.GOOGLE],
      });
      (bcrypt.hash as jest.Mock).mockResolvedValue('new-hashed');
      mockUserService.updateUser.mockResolvedValue(undefined);
      mockUserService.clearToken.mockResolvedValue(undefined);

      await service.resetPassword('newPass123!', 'valid-token');

      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        'user-123',
        expect.objectContaining({
          providers: expect.arrayContaining([Provider.LOCAL, Provider.GOOGLE]),
        }),
      );
    });

    it('should send OTP if email not verified after reset', async () => {
      mockUserService.getToken.mockResolvedValue({
        expiresAt: new Date(Date.now() + 60000),
        userId: 'user-123',
      });
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        email: 'test@test.com',
        name: 'Test',
        isEmailVerified: false,
        providers: [Provider.LOCAL],
      });
      (bcrypt.hash as jest.Mock).mockResolvedValue('new-hashed');
      mockUserService.updateUser.mockResolvedValue(undefined);
      mockUserService.clearToken.mockResolvedValue(undefined);
      mockUserService.saveToken.mockResolvedValue(undefined);
      mockMailService.sendOtpEmail.mockResolvedValue(undefined);

      await service.resetPassword('newPass123!', 'valid-token');

      expect(mockMailService.sendOtpEmail).toHaveBeenCalledTimes(1);
    });
  });

  describe('logout', () => {
    it('should clear refresh token on logout', async () => {
      mockUserService.findOne.mockResolvedValue({ id: 'user-123' });
      mockUserService.clearToken.mockResolvedValue(undefined);

      await service.logout('user-123');

      expect(mockUserService.clearToken).toHaveBeenCalledWith(
        TokenType.REFRESH,
        'user-123',
      );
    });

    it('should throw UnauthorizedException if user not found', async () => {
      mockUserService.findOne.mockResolvedValue(null);

      await expect(service.logout('user-123')).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('forceVerifyUser', () => {
    it('should force verify user in test environment', async () => {
      process.env.NODE_ENV = 'test';
      mockUserService.updateUser.mockResolvedValue(undefined);

      await service.forceVerifyUser('user-123');

      expect(mockUserService.updateUser).toHaveBeenCalledWith('user-123', {
        isEmailVerified: true,
      });
    });

    it('should throw ForbiddenException in non-test environment', async () => {
      process.env.NODE_ENV = 'production';

      await expect(service.forceVerifyUser('user-123')).rejects.toThrow(
        ForbiddenException,
      );

      process.env.NODE_ENV = 'test';
    });
  });

  describe('deleteTestUser', () => {
    it('should delete user in test environment', async () => {
      process.env.NODE_ENV = 'test';
      mockUserService.deleteTestUser.mockResolvedValue(undefined);

      await service.deleteTestUser('test@test.com');

      expect(mockUserService.deleteTestUser).toHaveBeenCalledWith(
        'test@test.com',
      );
    });

    it('should throw ForbiddenException in non-test environment', async () => {
      process.env.NODE_ENV = 'production';

      await expect(service.deleteTestUser('test@test.com')).rejects.toThrow(
        ForbiddenException,
      );

      process.env.NODE_ENV = 'test';
    });

    it('should call deleteTestDeletedEmail when fromDeleted=true', async () => {
      mockUserService.deleteTestDeletedEmail.mockResolvedValue(undefined);

      await service.deleteTestUser('test@test.com', true);

      expect(mockUserService.deleteTestDeletedEmail).toHaveBeenCalledWith(
        'test@test.com',
      );
      expect(mockUserService.deleteTestUser).not.toHaveBeenCalled();
    });
  });

  describe('generateTokens', () => {
    it('should return access and refresh tokens', async () => {
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

    it('should store hashed refresh token, not the raw JWT', async () => {
      mockUserService.saveToken.mockResolvedValue(undefined);

      await service.generateTokens({
        id: 'user-123',
        email: 'test@test.com',
        isEmailVerified: true,
      });

      const storedToken = mockUserService.saveToken.mock.calls[0][1];
      expect(storedToken).not.toBe('mock-token');
      expect(storedToken).toHaveLength(64);
    });
  });

  describe('forgotPassword', () => {
    it('should return generic message if user not found (email enumeration prevention)', async () => {
      mockUserService.findOne.mockResolvedValue(null);

      const result = await service.forgotPassword('notfound@test.com');

      expect(result).toEqual({
        message: 'If email exists, reset link has been sent',
      });
      expect(mockMailService.sendResetPasswordEmail).not.toHaveBeenCalled();
    });

    it('should send reset email and return generic message if user exists', async () => {
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

    it('should clear token and still return generic message if email sending fails', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        email: 'test@test.com',
        name: 'Test',
      });
      mockUserService.saveToken.mockResolvedValue(undefined);
      mockMailService.sendResetPasswordEmail.mockRejectedValue(
        new Error('SMTP error'),
      );

      const result = await service.forgotPassword('test@test.com');

      expect(result).toEqual({
        message: 'If email exists, reset link has been sent',
      });
      expect(mockUserService.clearToken).toHaveBeenCalledWith(
        TokenType.PASSWORD_RESET,
        'user-123',
      );
    });
  });

  describe('refreshTokens', () => {
    it('should return new token pair on valid refresh', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        email: 'test@test.com',
        isEmailVerified: true,
      });
      mockUserService.clearToken.mockResolvedValue({ affected: 1 });
      mockUserService.saveToken.mockResolvedValue(undefined);

      const result = await service.refreshTokens(
        'user-123',
        'old-refresh-token',
      );

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
    });

    it('should hash the old token before passing to clearToken', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        email: 'test@test.com',
        isEmailVerified: true,
      });
      mockUserService.clearToken.mockResolvedValue({ affected: 1 });
      mockUserService.saveToken.mockResolvedValue(undefined);

      await service.refreshTokens('user-123', 'raw-token');

      const passedHash = mockUserService.clearToken.mock.calls[0][2];
      expect(passedHash).not.toBe('raw-token');
      expect(passedHash).toHaveLength(64);
    });

    it('should throw UnauthorizedException if user not found', async () => {
      mockUserService.findOne.mockResolvedValue(null);

      await expect(
        service.refreshTokens('user-123', 'old-token'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if old token hash does not match', async () => {
      mockUserService.findOne.mockResolvedValue({
        id: 'user-123',
        email: 'test@test.com',
        isEmailVerified: true,
      });
      mockUserService.clearToken.mockResolvedValue({ affected: 0 });

      await expect(
        service.refreshTokens('user-123', 'wrong-token'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });
});
