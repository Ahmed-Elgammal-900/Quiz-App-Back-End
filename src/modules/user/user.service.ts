import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { DeletedUser } from './entities/deletedUser.entity';
import { FindOptionsWhere, Repository } from 'typeorm';
import { CreateAuthDto } from '../auth/dto/signup.dto';
import { ConflictException, NotFoundException } from '@nestjs/common';
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
    private deletedUserRepositry: Repository<DeletedUser>,
  ) {}
  async createUser(createAuthDto: CreateAuthDto) {
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

    return plainToInstance(UserResponseDto, user);
  }

  async findOne(field: {}) {
    const user = await this.userRepository.findOne({ where: field });

    if (!user) {
      throw new NotFoundException('user not found');
    }

    return user;
  }

  async findDeletedByEmail(email: string) {
    const user = await this.deletedUserRepositry.exists({ where: { email } });

    if (!user) {
      throw new NotFoundException('user not found');
    }

    return user;
  }

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
      user.providers = [...user.providers, Provider.GOOGLE];
      await this.userRepository.save(user);
    }

    user = this.userRepository.create({
      email,
      name,
      googleId,
      providers: [Provider.GOOGLE],
    });

    return await this.userRepository.save(user);
  }

  async deleteUser(user: { id: string; email: string }) {
    const deletedEmail = this.deletedUserRepositry.create({
      email: user.email,
    });

    await this.deletedUserRepositry.save(deletedEmail);

    const result = await this.userRepository.delete(user.id);

    if (result.affected === 0) {
      throw new NotFoundException('User not found');
    }

    return { message: 'Account deleted successfully' };
  }

  async updateUser(id: string, fields: {}) {
    const result = await this.userRepository.update(id, fields);
    if (result.affected === 0) {
      throw new NotFoundException('User not found');
    }
  }

  async saveToken(
    userId: string,
    hashedToken: string,
    type: TokenType,
    expiresAt: Date,
  ) {
    await this.tokenRepository.delete({ userId, type });

    return this.tokenRepository.save({
      userId,
      token: hashedToken,
      type,
      expiresAt,
      isUsed: false,
      isRevoked: false,
      attempts: 0,
      lastSentAt: new Date(),
    });
  }

  async getToken(type: TokenType, userId?: string, tokenValue?: string) {
    const where: FindOptionsWhere<Token> = { type };

    if (userId) where.userId = userId;
    if (tokenValue) where.token = tokenValue;

    const token = await this.tokenRepository.findOne({ where });

    return token;
  }

  async clearToken(type: TokenType, userId?: string, tokenValue?: string) {
    const where: FindOptionsWhere<Token> = { type };

    if (userId) where.userId = userId;
    if (tokenValue) where.token = tokenValue;

    await this.tokenRepository.delete(where);
  }

  async incrementAttempts(userId: string) {
    await this.tokenRepository.increment(
      { userId, type: TokenType.EMAIL_VERIFY },
      'attempts',
      1,
    );
  }

  async verifyUser(userId: string) {
    await this.userRepository.update(userId, {
      isEmailVerified: true,
    });

    await this.clearToken(TokenType.EMAIL_VERIFY, userId);
  }
}
