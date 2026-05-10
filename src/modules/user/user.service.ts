import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { DeletedUser } from './entities/deletedUser.entity';
import { FindOptionsWhere, Repository, DataSource } from 'typeorm';
import { CreateAuthDto } from '../auth/dto/signup.dto';
import {
  ConflictException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { plainToInstance } from 'class-transformer';
import { UserResponseDto } from './dto/user-response.dto';
import { Token } from './entities/token.entity';
import { TokenType } from '../auth/constants/token-type.constant';
import { Provider } from './constants/provider.constant';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    @InjectRepository(Token)
    private tokenRepository: Repository<Token>,
    @InjectRepository(DeletedUser)
    private deletedUserRepository: Repository<DeletedUser>,
    private dataSource: DataSource,
  ) {}

  /**
   * Create new user into database
   * @param createAuthDto - The data transfer object containing user creation data
   * @returns A promise with new user type based on exposed fields
   */
  async createUser(createAuthDto: CreateAuthDto): Promise<UserResponseDto> {
    const { email, password, name } = createAuthDto;
    const deletedUser = await this.findDeletedByEmail(email);

    if (deletedUser) {
      throw new ConflictException('this account was deleted');
    }

    const currentUser = await this.findOne({ email });

    if (currentUser) {
      throw new ConflictException('you already have account go to login page');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = this.userRepository.create({
      email: email,
      password: hashedPassword,
      name: name,
    });

    await this.userRepository.save(user);

    return plainToInstance(UserResponseDto, user, {
      excludeExtraneousValues: true,
    });
  }

  /**
   * Find a user by given conditions
   * @param field - query conditions
   * @returns User if found, null otherwise
   */
  async findOne(field: FindOptionsWhere<User>) {
    return this.userRepository.findOne({ where: field });
  }

  /**
   * Check if deleted user exist by email
   * @param email
   * @returns true if exist, false otherwise
   */
  async findDeletedByEmail(email: string) {
    return this.deletedUserRepository.exists({ where: { email } });
  }

  /**
   * Find google user if not create new user
   * @param profile user info from google
   * @returns User after creation in database
   */
  async findOrCreateGoogleUser(profile: {
    email: string;
    name: string;
    googleId: string;
  }) {
    const { name, email, googleId } = profile;

    let user = await this.userRepository.findOne({
      where: { googleId: googleId },
    });
    if (user) return user;

    user = await this.findOne({ email });
    if (user) {
      user.googleId = googleId;
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
      }
      if (!user.providers.includes(Provider.GOOGLE)) {
        user.providers = [...user.providers, Provider.GOOGLE];
      }
      return await this.userRepository.save(user);
    }

    user = this.userRepository.create({
      email,
      name,
      googleId,
      providers: [Provider.GOOGLE],
      isEmailVerified: true,
    });

    return await this.userRepository.save(user);
  }

  /**
   * Delete user from user entity
   * @param user user from jwt guard
   * @returns message if deletion success
   */
  async deleteUser(user: { id: string; email: string }) {
    await this.dataSource.transaction(async (manager) => {
      const result = await manager.delete(User, user.id);
      if (result.affected === 0) {
        throw new NotFoundException('User not found');
      }
      const deletedEmail = manager.create(DeletedUser, { email: user.email });
      await manager.save(deletedEmail);
    });
    return { message: 'Account deleted successfully' };
  }

  /**
   * Update user based on id
   * NOTE: Callers are responsible for pre-processing sensitive fields
   * (e.g., password must be hashed before being passed here).
   * @param id User id
   * @param fields user properties to be updated
   * @returns void
   */
  async updateUser(id: string, fields: Partial<User>) {
    const result = await this.userRepository.update(id, fields);
    if (result.affected === 0) {
      throw new NotFoundException('User not found');
    }
  }

  /**
   * Save user token — replaces existing token of same type
   * @param userId - ID of the user
   * @param hashedToken - hashed token string
   * @param type - token type (refresh, reset, verify...)
   * @param expiresAt - token expiration date
   * @returns void
   */
  async saveToken(
    userId: string,
    hashedToken: string,
    type: TokenType,
    expiresAt: Date,
  ) {
    await this.tokenRepository.upsert(
      {
        userId,
        token: hashedToken,
        type,
        expiresAt,
        attempts: 0,
        lastSentAt: new Date(),
      },
      {
        conflictPaths: ['userId', 'type'],
      },
    );
  }

  /**
   * Retrieve a token based on type and optional filters
   * @param type - token type to search for
   * @param userId - (optional) filter by user ID
   * @param tokenValue - (optional) filter by token value
   * @returns Token if found, null otherwise
   */
  async getToken(type: TokenType, userId?: string, tokenValue?: string) {
    if (!userId && !tokenValue) {
      throw new BadRequestException('userId or tokenValue is required');
    }
    const where: FindOptionsWhere<Token> = { type };

    if (userId) where.userId = userId;
    if (tokenValue) where.token = tokenValue;

    const token = await this.tokenRepository.findOne({ where });

    return token;
  }

  /**
   * Delete a token based on type and optional filters
   * @param type - token type to delete
   * @param userId - (optional) filter by user ID
   * @param tokenValue - (optional) filter by token value
   * @returns void
   */
  async clearToken(type: TokenType, userId?: string, tokenValue?: string) {
    if (!userId && !tokenValue) {
      throw new BadRequestException('userId or tokenValue is required');
    }
    const where: FindOptionsWhere<Token> = { type };

    if (userId) where.userId = userId;
    if (tokenValue) where.token = tokenValue;

    return await this.tokenRepository.delete(where);
  }

  /**
   * Increment failed verification attempts for a user
   * @param userId - ID of the user
   * @returns void
   */
  async incrementAttempts(userId: string, type = TokenType.EMAIL_VERIFY) {
    await this.tokenRepository.increment({ userId, type }, 'attempts', 1);
  }

  /**
   * Mark user email as verified and clear verification token
   * @param userId - ID of the user to verify
   * @returns void
   */
  async verifyUser(userId: string) {
    await this.userRepository.update(userId, {
      isEmailVerified: true,
    });

    await this.clearToken(TokenType.EMAIL_VERIFY, userId);
  }

  /**
   * Deletes a user by email address. Intended exclusively for e2e testing.
   * Cleans up test users between runs to ensure a fresh state.
   *
   * @param email - The email address of the user to delete
   * @returns Promise<void>
   *
   * @example
   * await userService.deleteTestUser('test@email.com');
   */
  async deleteTestUser(email: string): Promise<void> {
    if (!(process.env.NODE_ENV === 'test')) {
      throw new Error('deleteTestUser only in test environment');
    }
    await this.userRepository.delete({ email });
  }

  /**
   * Deletes a deleted user record by email. **Test environment only.**
   * Cleans up deleted test users at the start of a test to ensure nothing blocks user registration.
   *
   * @param email - The email of the deleted user record to remove.
   * @throws {Error} If called outside of the test environment.
   */
  async deleteTestDeletedEmail(email: string): Promise<void> {
    if (!(process.env.NODE_ENV === 'test')) {
      throw new Error('deleteTestDeletedEmail only in test environment');
    }
    await this.deletedUserRepository.delete({ email });
  }
}
