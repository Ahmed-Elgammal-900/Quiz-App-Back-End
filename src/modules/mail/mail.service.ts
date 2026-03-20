import { Injectable } from '@nestjs/common';
import { render } from '@react-email/components';
import { ConfigService } from '@nestjs/config';
import PasswordResetEmail from './templates/reset-password';
import OTPEmailTemplate from './templates/email-verification';
import * as nodemailer from 'nodemailer';

/**
 * Service responsible for sending transactional emails via Gmail SMTP.
 *
 * Handles password reset and OTP verification emails using React Email
 * templates rendered to HTML and delivered through Nodemailer.
 */
@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;
  private readonly frontEndOrigin: string;

  /**
   * Creates the MailService and initializes the Nodemailer transporter.
   *
   * Reads `GMAIL_USER`, `GMAIL_APP_PASSWORD`, and `FRONT_END_ORIGIN` from
   * the application config. Throws if any value is missing or if
   * `FRONT_END_ORIGIN` is not a valid absolute URL.
   *
   * @param configService - NestJS ConfigService used to read environment variables.
   * @throws {Error} If any required mail configuration value is absent.
   * @throws {Error} If `FRONT_END_ORIGIN` is not a valid absolute URL.
   */
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

  /**
   * Sends a password-reset email containing a tokenized reset link.
   *
   * The reset URL is built by appending `/reset-password?token=<resetToken>`
   * to `FRONT_END_ORIGIN` and embedded in the `PasswordResetEmail` template.
   *
   * @param email - Recipient's email address.
   * @param resetToken - Raw reset token included in the reset URL (validated server-side via stored hash).
   * @param name - Optional display name used to personalize the email greeting.
   * @returns The Nodemailer send-mail result object.
   * @throws {Error} If the underlying SMTP transport fails to deliver the message.
   */
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

  /**
   * Sends a one-time password (OTP) email for email address verification.
   *
   * Renders the `OTPEmailTemplate` with the provided OTP and expiry window,
   * then dispatches it via the configured Gmail transporter.
   *
   * @param email - Recipient's email address.
   * @param otp - The one-time password code to include in the email.
   * @param name - Optional display name used to personalize the email greeting.
   * @param expiryMins - Minutes until the OTP expires (defaults to `5`).
   * @returns The Nodemailer send-mail result object.
   * @throws {Error} If the underlying SMTP transport fails to deliver the message.
   */
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
