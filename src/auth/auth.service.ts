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
import { LoginDto } from './dto/login.dto';
import * as crypto from 'crypto';
import { MailService } from 'src/mail/mail.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    @InjectRepository(DeletedUser)
    private deletedUserRepositry: Repository<DeletedUser>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailService: MailService,
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

  async validateLocalUser(loginDto: LoginDto) {
    const { email, password } = loginDto;
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

  async requestPasswordReset(email: string) {
    const deletedUser = await this.deletedUserRepositry.findOne({
      where: { email: email },
    });

    if (deletedUser) {
      return { message: 'If email exists, reset link has been sent' };
    }
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      return { message: 'If email exists, reset link has been sent' };
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = new Date(Date.now() + 5 * 60 * 1000);
    await this.userRepository.save(user);

    const data = await this.mailService.sendResetPasswordEmail(
      email,
      resetToken,
    );

    return { message: 'If email exists, reset link has been sent', data: data };
  }

  async resetPassword(newPassword: string, token: string) {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await this.userRepository.findOne({
      where: {
        passwordResetToken: hashedToken,
      },
    });

    if (
      !user ||
      !user.passwordResetExpires ||
      user.passwordResetExpires < new Date()
    ) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.passwordResetToken = null;
    user.passwordResetExpires = null;
    await this.userRepository.save(user);

    return user;
  }

  async deleteUser(user: User) {
    const deletedEmail = this.deletedUserRepositry.create({
      email: user.email,
    });

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

  async updateAccessToken(user: { userId: string; email: string }) {
    const payload = { sub: user.userId, email: user.email };

    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_SECRET')!,
      expiresIn: '15m',
    });

    return { accessToken };
  }
}
