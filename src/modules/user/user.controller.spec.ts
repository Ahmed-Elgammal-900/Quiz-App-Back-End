import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { ConfigService } from '@nestjs/config';
import { NotFoundException } from '@nestjs/common';
import { Response } from 'express';

const mockUser = {
  id: 'user-123',
  name: 'Test User',
  email: 'test-user@example.com',
} as any;

const mockResponse = (): Response =>
  ({ clearCookie: jest.fn() }) as unknown as Response;

const mockUserService = {
  findOne: jest.fn(),
  deleteUser: jest.fn(),
};

const mockConfigService = {
  get: jest.fn().mockReturnValue('development'),
};

describe('UserController', () => {
  let controller: UserController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      providers: [
        { provide: UserService, useValue: mockUserService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    controller = module.get<UserController>(UserController);
    jest.clearAllMocks();
  });

  describe('GET /user', () => {
    it('should return name and email when user exists', async () => {
      mockUserService.findOne.mockResolvedValue(mockUser);

      const result = await controller.getUser(mockUser.id);

      expect(result).toEqual({ name: mockUser.name, email: mockUser.email });
      expect(mockUserService.findOne).toHaveBeenCalledWith({ id: mockUser.id });
    });

    it('should throw NotFoundException when user does not exist', async () => {
      mockUserService.findOne.mockResolvedValue(null);

      await expect(controller.getUser(mockUser.id)).rejects.toThrow(
        new NotFoundException(`User with ID ${mockUser.id} not found`),
      );
    });
  });

  describe('DELETE /user', () => {
    it('should delete user and clear both cookies', async () => {
      mockUserService.deleteUser.mockResolvedValue({
        message: 'Account deleted successfully',
      });

      const res = mockResponse();
      const result = await controller.remove(mockUser, res);

      expect(result).toEqual({ message: 'Account deleted successfully' });
      expect(mockUserService.deleteUser).toHaveBeenCalledWith(mockUser);
      expect(res.clearCookie).toHaveBeenCalledTimes(2);
      expect(res.clearCookie).toHaveBeenCalledWith(
        'access_token',
        expect.any(Object),
      );
      expect(res.clearCookie).toHaveBeenCalledWith(
        'refresh_token',
        expect.any(Object),
      );
    });

    it('should propagate error if deleteUser throws', async () => {
      mockUserService.deleteUser.mockRejectedValue(new Error('DB failure'));

      await expect(controller.remove(mockUser, mockResponse())).rejects.toThrow(
        'DB failure',
      );
    });

    it('should clear cookies with secure: false in development', async () => {
      mockUserService.deleteUser.mockResolvedValue({ message: 'ok' });
      mockConfigService.get.mockReturnValue('development');

      const res = mockResponse();
      await controller.remove(mockUser, res);

      expect(res.clearCookie).toHaveBeenCalledWith('access_token', {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
      });
    });

    it('should clear cookies with secure: true in production', async () => {
      mockUserService.deleteUser.mockResolvedValue({ message: 'ok' });
      mockConfigService.get.mockReturnValue('production');

      const res = mockResponse();
      await controller.remove(mockUser, res);

      expect(res.clearCookie).toHaveBeenCalledWith('access_token', {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
      });
    });
  });
});
