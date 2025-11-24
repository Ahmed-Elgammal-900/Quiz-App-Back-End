import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { DeletedUser } from './entities/deletedUser.entity';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { GoogleDto } from './dto/google-auth.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    @InjectRepository(DeletedUser)
    private deletedUserRepositry: Repository<DeletedUser>,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}
  async createUser(createAuthDto: CreateAuthDto) {
    const { email, password, name } = createAuthDto;
    const deletedUser = await this.deletedUserRepositry.exists({
      where: { email: email },
    });
    if (deletedUser) {
      throw new BadRequestException('this account was deleted');
    }
    const currentUser = await this.userRepository.exists({
      where: { email: email },
    });

    if (currentUser) {
      throw new BadRequestException(
        'you already have account go to login page',
      );
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = this.userRepository.create({
      email: email,
      password: hashedPassword,
      name: name,
    });

    return await this.userRepository.save(user);
  }

  async validateGoogleUser(googleDto: GoogleDto) {
    const { name, email, googleId } = googleDto;
    const deletedUser = await this.deletedUserRepositry.exists({
      where: { email: email },
    });
    if (deletedUser) {
      throw new BadRequestException('this account was deleted');
    }

    let user = await this.userRepository.findOne({
      where: { googleId: googleId },
    });

    if (!user) {
      user = await this.userRepository.findOne({ where: { email: email } });
      if (user) {
        user.googleId = googleId;
        await this.userRepository.save(user);
      } else {
        user = this.userRepository.create({
          email: email,
          name: name,
          googleId: googleId,
          provider: 'google',
        });
        await this.userRepository.save(user);
      }
    }

    return user;
  }

  async validateLocalUser(email: string, password: string) {
    const deletedUser = await this.deletedUserRepositry.exists({
      where: { email: email },
    });
    if (deletedUser) {
      throw new BadRequestException('this account was deleted');
    }

    const user = await this.userRepository.findOne({ where: { email: email } });

    if (!user) {
      throw new NotFoundException('User Not Found');
    }

    const truePassword = await bcrypt.compare(password, user.password);

    if (!truePassword) {
      throw new BadRequestException('Password Or Email Incorrect');
    }

    return user;
  }

  async updatePassword() {}

  async deleteUser(userId: string, email: string) {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const deletedEmail = this.deletedUserRepositry.create({ email: email });

    await this.deletedUserRepositry.save(deletedEmail);

    await this.userRepository.remove(user);

    return { message: 'Account deleted successfully' };
  }

  generateTokens(user: User) {
    const payload = { sub: user.id, email: user.email };

    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_SECRET')!,
      expiresIn: '15m',
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET')!,
      expiresIn: '7d',
    });

    return { accessToken, refreshToken };
  }

  async updateAccessToken(userId: string) {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const payload = { sub: user.id, email: user.email };

    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_SECRET')!,
      expiresIn: '15m',
    });

    return { accessToken };
  }
}
