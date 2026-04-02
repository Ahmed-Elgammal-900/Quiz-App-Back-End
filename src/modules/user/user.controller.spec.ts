import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { ConfigService } from '@nestjs/config';
import { Response } from 'express';

const mockResponse = () => {
  const res: Partial<Response> = {
    clearCookie: jest.fn(),
  };
  return res as Response;
};

const mockUserService = {
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

  describe('DELETE /user', () => {
    it('should delete user and clear cookies', async () => {
      mockUserService.deleteUser.mockResolvedValue({
        message: 'Account deleted successfully',
      });

      const res = mockResponse();
      const user = { id: 'user-123', email: 'test@test.com' } as any;

      const result = await controller.remove(user, res);

      expect(result).toEqual({ message: 'Account deleted successfully' });
      expect(mockUserService.deleteUser).toHaveBeenCalledWith(user);
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
      mockUserService.deleteUser.mockRejectedValue(new Error('Not found'));

      const res = mockResponse();
      await expect(
        controller.remove(
          { id: 'user-123', email: 'test@test.com' } as any,
          res,
        ),
      ).rejects.toThrow('Not found');
    });

    it('should clear cookies with correct options in development', async () => {
      mockUserService.deleteUser.mockResolvedValue({
        message: 'Account deleted successfully',
      });
      mockConfigService.get.mockReturnValue('development');

      const res = mockResponse();
      await controller.remove(
        { id: 'user-123', email: 'test@test.com' } as any,
        res,
      );

      expect(res.clearCookie).toHaveBeenCalledWith('access_token', {
        httpOnly: true,
        secure: false,
        sameSite: 'strict',
        path: '/',
      });
    });

    it('should set secure cookies in production', async () => {
      mockUserService.deleteUser.mockResolvedValue({
        message: 'Account deleted successfully',
      });
      mockConfigService.get.mockReturnValue('production');

      const res = mockResponse();
      await controller.remove(
        { id: 'user-123', email: 'test@test.com' } as any,
        res,
      );

      expect(res.clearCookie).toHaveBeenCalledWith('access_token', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/',
      });
    });
  });
});
