import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { Response } from 'express';
import { BadRequestException, NotFoundException } from '@nestjs/common';

const mockResponse = () => {
  const res: Partial<Response> = {
    cookie: jest.fn(),
    clearCookie: jest.fn(),
  };
  return res as Response;
};

const mockAuthService = {
  createUser: jest.fn(),
  validateLocalUser: jest.fn(),
  generateTokens: jest.fn(),
  generateOAuthCode: jest.fn(),
  refreshTokens: jest.fn(),
  changePassword: jest.fn(),
  forgotPassword: jest.fn(),
  resetPassword: jest.fn(),
  verifyOtp: jest.fn(),
  resendOtp: jest.fn(),
  consumeOAuthCode: jest.fn(),
  logout: jest.fn(),
};

const mockConfigService = {
  get: jest.fn().mockReturnValue('development'),
};

describe('AuthController', () => {
  let controller: AuthController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    jest.clearAllMocks();
  });

  // signup

  describe('POST /auth/signup', () => {
    it('should register a new user and return userId', async () => {
      mockAuthService.createUser.mockResolvedValue({ id: 'user-123' });

      const result = await controller.create({
        name: 'Test',
        email: 'test@test.com',
        password: 'Pass123!',
        confirmPassword: 'Pass123!',
      } as any);

      expect(result).toEqual({ message: 'signup success', userId: 'user-123' });
      expect(mockAuthService.createUser).toHaveBeenCalledTimes(1);
    });
  });

  // login

  describe('POST /auth/login', () => {
    it('should login verified user and set cookies', async () => {
      const user = { id: 'user-123', isEmailVerified: true };
      mockAuthService.validateLocalUser.mockResolvedValue(user);
      mockAuthService.generateTokens.mockResolvedValue({
        accessToken: 'access',
        refreshToken: 'refresh',
      });

      const res = mockResponse();
      const result = await controller.login(
        { email: 'test@test.com', password: 'Pass123!' },
        res,
      );

      expect(result.message).toBe('login success');
      expect(result.isEmailVerified).toBe(true);
      expect(res.cookie).toHaveBeenCalledTimes(2);
      expect(mockAuthService.generateTokens).toHaveBeenCalledWith(user);
    });

    it('should not set cookies if email not verified', async () => {
      const user = { id: 'user-123', isEmailVerified: false };
      mockAuthService.validateLocalUser.mockResolvedValue(user);

      const res = mockResponse();
      const result = await controller.login(
        { email: 'test@test.com', password: 'Pass123!' },
        res,
      );

      expect(result.message).toBe('otp verification required');
      expect(res.cookie).not.toHaveBeenCalled();
      expect(mockAuthService.generateTokens).not.toHaveBeenCalled();
    });
  });

  // refresh token

  describe('POST /auth/refresh-token', () => {
    it('should rotate tokens and set new cookies', async () => {
      mockAuthService.refreshTokens.mockResolvedValue({
        accessToken: 'new-access',
        refreshToken: 'new-refresh',
      });

      const res = mockResponse();
      const result = await controller.refresh(
        { id: 'user-123', refreshToken: 'old-refresh' } as any,
        res,
      );

      expect(result).toEqual({ message: 'success access token' });
      expect(res.cookie).toHaveBeenCalledTimes(2);
    });
  });

  // change password

  describe('PATCH /auth/change-password', () => {
    it('should change password and return success message', async () => {
      mockAuthService.changePassword.mockResolvedValue(undefined);

      const result = await controller.changePassword(
        { id: 'user-123' } as any,
        {
          currentPassword: 'old',
          newPassword: 'new',
          confirmPassword: 'new',
        } as any,
      );

      expect(result).toEqual({ message: 'password changed successfully' });
      expect(mockAuthService.changePassword).toHaveBeenCalledWith('user-123', {
        currentPassword: 'old',
        newPassword: 'new',
        confirmPassword: 'new',
      });
    });

    it('should change password without currentPassword (OAuth account)', async () => {
      mockAuthService.changePassword.mockResolvedValue(undefined);

      const result = await controller.changePassword(
        { id: 'user-123' } as any,
        { newPassword: 'new', confirmPassword: 'new' } as any,
      );

      expect(result).toEqual({ message: 'password changed successfully' });
    });

    it('should throw if authService throws BadRequestException', async () => {
      mockAuthService.changePassword.mockRejectedValue(
        new BadRequestException('Current password is incorrect'),
      );

      await expect(
        controller.changePassword(
          { id: 'user-123' } as any,
          {
            currentPassword: 'wrong',
            newPassword: 'new',
            confirmPassword: 'new',
          } as any,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw if authService throws NotFoundException', async () => {
      mockAuthService.changePassword.mockRejectedValue(
        new NotFoundException('User not found'),
      );

      await expect(
        controller.changePassword(
          { id: 'user-123' } as any,
          {
            currentPassword: 'old',
            newPassword: 'new',
            confirmPassword: 'new',
          } as any,
        ),
      ).rejects.toThrow(NotFoundException);
    });
  });

  // forgot password

  describe('POST /auth/forget-password', () => {
    it('should return generic message regardless of email existence', async () => {
      mockAuthService.forgotPassword.mockResolvedValue({
        message: 'If email exists, reset link has been sent',
      });

      const result = await controller.forgetPassword({
        email: 'test@test.com',
      });

      expect(result).toEqual({
        message: 'If email exists, reset link has been sent',
      });
    });
  });

  // reset password

  describe('POST /auth/reset-password', () => {
    it('should reset password and set cookies for verified user', async () => {
      const user = { id: 'user-123', isEmailVerified: true };
      mockAuthService.resetPassword.mockResolvedValue(user);
      mockAuthService.generateTokens.mockResolvedValue({
        accessToken: 'access',
        refreshToken: 'refresh',
      });

      const res = mockResponse();
      const result = await controller.resetPassword(
        { password: 'newPass123!', resetToken: 'token' } as any,
        res,
      );

      expect(result.message).toBe('Password reset successful');
      expect(res.cookie).toHaveBeenCalledTimes(2);
    });

    it('should not set cookies if email not verified after reset', async () => {
      const user = { id: 'user-123', isEmailVerified: false };
      mockAuthService.resetPassword.mockResolvedValue(user);

      const res = mockResponse();
      const result = await controller.resetPassword(
        { password: 'newPass123!', resetToken: 'token' } as any,
        res,
      );

      expect(result.message).toBe(
        'Password reset successful, please verify your email',
      );
      expect(res.cookie).not.toHaveBeenCalled();
    });
  });

  // verify email

  describe('POST /auth/verify-email', () => {
    it('should verify email and set cookies', async () => {
      const user = { id: 'user-123', isEmailVerified: true };
      mockAuthService.verifyOtp.mockResolvedValue(user);
      mockAuthService.generateTokens.mockResolvedValue({
        accessToken: 'access',
        refreshToken: 'refresh',
      });

      const res = mockResponse();
      const result = await controller.verifyEmail(
        { id: 'user-123', otp: '123456' },
        res,
      );

      expect(result).toEqual({ message: 'email verified' });
      expect(res.cookie).toHaveBeenCalledTimes(2);
    });
  });

  // resend otp

  describe('POST /auth/resend-otp', () => {
    it('should resend OTP and return success message', async () => {
      mockAuthService.resendOtp.mockResolvedValue({
        message: 'OTP sent successfully',
      });

      const result = await controller.resendOtp({ id: 'user-123' });

      expect(result).toEqual({ message: 'OTP sent successfully' });
      expect(mockAuthService.resendOtp).toHaveBeenCalledWith('user-123');
    });
  });

  // verify access token

  describe('POST /auth/verify-access-token', () => {
    it('should return success true for valid token', async () => {
      const result = await controller.verifyAccessToken();
      expect(result).toEqual({ success: true });
    });
  });

  // exchange code

  describe('GET /auth/exchange', () => {
    it('should exchange OAuth code and set cookies', async () => {
      const user = { id: 'user-123', isEmailVerified: true };
      mockAuthService.consumeOAuthCode.mockResolvedValue(user);
      mockAuthService.generateTokens.mockResolvedValue({
        accessToken: 'access',
        refreshToken: 'refresh',
      });

      const res = mockResponse();
      const result = await controller.exchange(
        { code: 'oauth-code' } as any,
        res,
      );

      expect(result).toEqual({ success: true });
      expect(mockAuthService.consumeOAuthCode).toHaveBeenCalledWith(
        'oauth-code',
      );
      expect(mockAuthService.generateTokens).toHaveBeenCalledWith(user);
      expect(res.cookie).toHaveBeenCalledTimes(2);
    });
  });

  // logout

  describe('POST /auth/logout', () => {
    it('should logout user and clear cookies', async () => {
      mockAuthService.logout.mockResolvedValue(undefined);

      const res = mockResponse();
      const result = await controller.logout({ id: 'user-123' } as any, res);

      expect(result).toEqual({ message: 'logout success' });
      expect(res.clearCookie).toHaveBeenCalledTimes(2);
      expect(mockAuthService.logout).toHaveBeenCalledWith('user-123');
    });
  });
});
