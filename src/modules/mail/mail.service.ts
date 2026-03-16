import { Injectable } from '@nestjs/common';
import { render } from '@react-email/components';
import { ConfigService } from '@nestjs/config';
import PasswordResetEmail from './templates/reset-password';
import OTPEmailTemplate from './templates/email-verification';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;
  private readonly frontEndOrigin: string;
  constructor(private configService: ConfigService) {
    const gmailUser = this.configService.get<string>('GMAIL_USER');
    const gmailPass = this.configService.get<string>('GMAIL_APP_PASSWORD');
    const frontEndOrigin = this.configService.get<string>('FRONT_END_ORIGIN');

    if (!gmailUser || !gmailPass || !frontEndOrigin) {
      throw new Error('Mail configuration is incomplete');
    }

    try {
      this.frontEndOrigin = new URL(frontEndOrigin).toString();
    } catch {
      throw new Error('FRONT_END_ORIGIN must be a valid absolute URL');
    }

    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: gmailUser,
        pass: gmailPass,
      },
    });
  }

  async sendResetPasswordEmail(
    email: string,
    resetToken: string,
    name?: string,
  ) {
    const resetUrl = new URL('/reset-password', this.frontEndOrigin);
    resetUrl.searchParams.set('token', resetToken);

    const emailHtml = await render(
      PasswordResetEmail({
        resetUrl: resetUrl.toString(),
        recipientName: name,
      }),
    );

    try {
      return await this.transporter.sendMail({
        from: `"Quizzer" <${this.configService.get('GMAIL_USER')}>`,
        to: email,
        subject: 'Quizzer - Reset Password',
        html: emailHtml,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to send mail: ${message}`);
    }
  }

  async sendOtpEmail(
    email: string,
    otp: string,
    name?: string,
    expiryMins = 5,
  ) {
    const emailHtml = await render(
      OTPEmailTemplate({ otp, recipientName: name, expiryMins }),
    );

    try {
      return await this.transporter.sendMail({
        from: `"Quizzer" <${this.configService.get('GMAIL_USER')}>`,
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
