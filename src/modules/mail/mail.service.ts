import { Injectable } from '@nestjs/common';
import { render } from '@react-email/components';
import { ConfigService } from '@nestjs/config';
import PasswordResetEmail from './templates/reset-password';
import OTPEmailTemplate from './templates/email-verification';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;
  constructor(private configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: configService.get('GMAIL_USER'),
        pass: configService.get('GMAIL_APP_PASSWORD'),
      },
    });
  }

  async sendResetPasswordEmail(
    email: string,
    resetToken: string,
    name?: string,
  ) {
    const appUrl = this.configService.get<string>('ORIGIN');
    const resetUrl = `${appUrl}/reset-password?token=${resetToken}`;

    const emailHtml = await render(
      PasswordResetEmail({ resetUrl, recipientName: name, expiryMins: 10 }),
    );

    try {
      return await this.transporter.sendMail({
        to: email,
        subject: 'Quizzer - Reset Password',
        html: emailHtml,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to send mail: ${message}`);
    }
  }

  async sendOtpEmail(email: string, otp: string, name?: string) {
    const emailHtml = await render(
      OTPEmailTemplate({ otp, recipientName: name, expiryMins: 5 }),
    );

    try {
      return await this.transporter.sendMail({
        to: email,
        subject: 'Quizzer - Email Verification OTP',
        html: emailHtml,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to send mail: ${message}`);
    }
  }
}
