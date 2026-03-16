import { Test, TestingModule } from '@nestjs/testing';
import { UserService } from './user.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { DeletedUser } from './entities/deletedUser.entity';
import { Token } from './entities/token.entity';
import { DataSource } from 'typeorm';
import {
  ConflictException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { TokenType } from '../auth/constants/token-type.constant';
import { Provider } from './constants/provider.constant';

jest.mock('bcrypt');

const mockUserRepo = {
  create: jest.fn(),
  save: jest.fn(),
  findOne: jest.fn(),
  update: jest.fn(),
  delete: jest.fn(),
  increment: jest.fn(),
};

const mockTokenRepo = {
  upsert: jest.fn(),
  findOne: jest.fn(),
  delete: jest.fn(),
  increment: jest.fn(),
};

const mockDeletedUserRepo = {
  exists: jest.fn(),
  create: jest.fn(),
  save: jest.fn(),
};

const mockDataSource = {
  transaction: jest.fn(),
};

describe('UserService', () => {
  let service: UserService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        { provide: getRepositoryToken(User), useValue: mockUserRepo },
        { provide: getRepositoryToken(Token), useValue: mockTokenRepo },
        {
          provide: getRepositoryToken(DeletedUser),
          useValue: mockDeletedUserRepo,
        },
        { provide: DataSource, useValue: mockDataSource },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
    jest.clearAllMocks();
  });

  describe('createUser', () => {
    it('should create and return a new user', async () => {
      mockDeletedUserRepo.exists.mockResolvedValue(false);
      mockUserRepo.findOne.mockResolvedValue(null);
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');
      mockUserRepo.create.mockReturnValue({
        id: 'user-123',
        email: 'test@test.com',
        name: 'Test',
      });
      mockUserRepo.save.mockResolvedValue({
        id: 'user-123',
        email: 'test@test.com',
        name: 'Test',
      });

      const result = await service.createUser({
        name: 'Test',
        email: 'test@test.com',
        password: 'Pass123!',
      });

      expect(result).toBeDefined();
      expect(mockUserRepo.save).toHaveBeenCalledTimes(1);
    });

    it('should throw if account was deleted', async () => {
      mockDeletedUserRepo.exists.mockResolvedValue(true);

      await expect(
        service.createUser({
          name: 'Test',
          email: 'test@test.com',
          password: 'Pass123!',
        }),
      ).rejects.toThrow(ConflictException);
    });

    it('should throw if email already exists', async () => {
      mockDeletedUserRepo.exists.mockResolvedValue(false);
      mockUserRepo.findOne.mockResolvedValue({ id: 'user-123' });

      await expect(
        service.createUser({
          name: 'Test',
          email: 'test@test.com',
          password: 'Pass123!',
        }),
      ).rejects.toThrow(ConflictException);
    });
  });

  describe('findOne', () => {
    it('should return user if found', async () => {
      const user = { id: 'user-123', email: 'test@test.com' };
      mockUserRepo.findOne.mockResolvedValue(user);

      const result = await service.findOne({ email: 'test@test.com' });

      expect(result).toEqual(user);
    });

    it('should return null if not found', async () => {
      mockUserRepo.findOne.mockResolvedValue(null);

      const result = await service.findOne({ email: 'notfound@test.com' });

      expect(result).toBeNull();
    });
  });

  describe('findDeletedByEmail', () => {
    it('should return true if deleted user exists', async () => {
      mockDeletedUserRepo.exists.mockResolvedValue(true);

      const result = await service.findDeletedByEmail('deleted@test.com');

      expect(result).toBe(true);
    });

    it('should return false if not deleted', async () => {
      mockDeletedUserRepo.exists.mockResolvedValue(false);

      const result = await service.findDeletedByEmail('active@test.com');

      expect(result).toBe(false);
    });
  });

  describe('findOrCreateGoogleUser', () => {
    const profile = {
      email: 'google@test.com',
      name: 'Google User',
      googleId: 'google-123',
    };

    it('should return existing user by googleId', async () => {
      const user = { id: 'user-123', googleId: 'google-123' };
      mockUserRepo.findOne.mockResolvedValue(user);

      const result = await service.findOrCreateGoogleUser(profile);

      expect(result).toEqual(user);
    });

    it('should link googleId to existing email user', async () => {
      const user = {
        id: 'user-123',
        email: 'google@test.com',
        googleId: null,
        providers: [],
      };
      mockUserRepo.findOne
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(user);
      mockUserRepo.save.mockResolvedValue({ ...user, googleId: 'google-123' });

      const result = await service.findOrCreateGoogleUser(profile);

      expect(result.googleId).toBe('google-123');
      expect(mockUserRepo.save).toHaveBeenCalledTimes(1);
    });

    it('should create new user if not found', async () => {
      mockUserRepo.findOne.mockResolvedValue(null);
      const newUser = {
        id: 'user-123',
        ...profile,
        providers: [Provider.GOOGLE],
      };
      mockUserRepo.create.mockReturnValue(newUser);
      mockUserRepo.save.mockResolvedValue(newUser);

      const result = await service.findOrCreateGoogleUser(profile);

      expect(result).toEqual(newUser);
      expect(mockUserRepo.create).toHaveBeenCalledTimes(1);
    });
  });

  describe('deleteUser', () => {
    it('should delete user and add to deleted list', async () => {
      mockDataSource.transaction.mockImplementation(async (cb) => {
        const manager = {
          delete: jest.fn().mockResolvedValue({ affected: 1 }),
          create: jest.fn().mockReturnValue({ email: 'test@test.com' }),
          save: jest.fn().mockResolvedValue(undefined),
        };
        await cb(manager);
      });

      const result = await service.deleteUser({
        id: 'user-123',
        email: 'test@test.com',
      });

      expect(result).toEqual({ message: 'Account deleted successfully' });
    });

    it('should throw if user not found', async () => {
      mockDataSource.transaction.mockImplementation(async (cb) => {
        const manager = {
          delete: jest.fn().mockResolvedValue({ affected: 0 }),
          create: jest.fn(),
          save: jest.fn(),
        };
        await cb(manager);
      });

      await expect(
        service.deleteUser({ id: 'user-123', email: 'test@test.com' }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateUser', () => {
    it('should update user successfully', async () => {
      mockUserRepo.update.mockResolvedValue({ affected: 1 });

      await service.updateUser('user-123', { isEmailVerified: true });

      expect(mockUserRepo.update).toHaveBeenCalledWith('user-123', {
        isEmailVerified: true,
      });
    });

    it('should throw if user not found', async () => {
      mockUserRepo.update.mockResolvedValue({ affected: 0 });

      await expect(
        service.updateUser('user-123', { isEmailVerified: true }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('saveToken', () => {
    it('should upsert token', async () => {
      mockTokenRepo.upsert.mockResolvedValue(undefined);

      await service.saveToken(
        'user-123',
        'hashed-token',
        TokenType.REFRESH,
        new Date(),
      );

      expect(mockTokenRepo.upsert).toHaveBeenCalledTimes(1);
    });
  });

  describe('getToken', () => {
    it('should return token by userId', async () => {
      const token = { id: 'token-123', type: TokenType.REFRESH };
      mockTokenRepo.findOne.mockResolvedValue(token);

      const result = await service.getToken(TokenType.REFRESH, 'user-123');

      expect(result).toEqual(token);
    });

    it('should return token by tokenValue', async () => {
      const token = { id: 'token-123', type: TokenType.REFRESH };
      mockTokenRepo.findOne.mockResolvedValue(token);

      const result = await service.getToken(
        TokenType.REFRESH,
        undefined,
        'hashed-token',
      );

      expect(result).toEqual(token);
    });

    it('should throw if neither userId nor tokenValue provided', async () => {
      await expect(service.getToken(TokenType.REFRESH)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('clearToken', () => {
    it('should delete token by userId', async () => {
      mockTokenRepo.delete.mockResolvedValue(undefined);

      await service.clearToken(TokenType.REFRESH, 'user-123');

      expect(mockTokenRepo.delete).toHaveBeenCalledWith({
        type: TokenType.REFRESH,
        userId: 'user-123',
      });
    });

    it('should throw if neither userId nor tokenValue provided', async () => {
      await expect(service.clearToken(TokenType.REFRESH)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('incrementAttempts', () => {
    it('should increment attempts for user', async () => {
      mockTokenRepo.increment.mockResolvedValue(undefined);

      await service.incrementAttempts('user-123');

      expect(mockTokenRepo.increment).toHaveBeenCalledWith(
        { userId: 'user-123', type: TokenType.EMAIL_VERIFY },
        'attempts',
        1,
      );
    });
  });

  describe('verifyUser', () => {
    it('should verify user and clear token', async () => {
      mockUserRepo.update.mockResolvedValue({ affected: 1 });
      mockTokenRepo.delete.mockResolvedValue(undefined);

      await service.verifyUser('user-123');

      expect(mockUserRepo.update).toHaveBeenCalledWith('user-123', {
        isEmailVerified: true,
      });
      expect(mockTokenRepo.delete).toHaveBeenCalledTimes(1);
    });
  });

  describe('deleteTestUser', () => {
    it('should delete user by email', async () => {
      mockUserRepo.delete.mockResolvedValue(undefined);

      await service.deleteTestUser('test@test.com');

      expect(mockUserRepo.delete).toHaveBeenCalledWith({
        email: 'test@test.com',
      });
    });
  });
});
