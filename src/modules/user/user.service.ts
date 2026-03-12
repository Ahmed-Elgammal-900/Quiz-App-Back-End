import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { DeletedUser } from './entities/deletedUser.entity';
import { FindOptionsWhere, Repository } from 'typeorm';
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
  ) {}

  /**
   * Create new user into database
   * @param createAuthDto - The data transfer object containing user creation data
   * @returns A promise with new user type based on exosed fields
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
    });

    return await this.userRepository.save(user);
  }

  /**
   * Delete user from user entity
   * @param user user from jwt guard
   * @returns message if deletin success
   */
  async deleteUser(user: { id: string; email: string }) {
    const result = await this.userRepository.delete(user.id);

    if (result.affected === 0) {
      throw new NotFoundException('User not found');
    }

    const deletedEmail = this.deletedUserRepository.create({
      email: user.email,
    });

    await this.deletedUserRepository.save(deletedEmail);

    return { message: 'Account deleted successfully' };
  }

  /**
   * Update user based on id
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
        conflictPaths: ['userId', 'type'], // matches your @Index
        skipUpdateIfNoValuesChanged: true,
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

    await this.tokenRepository.delete(where);
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
}
