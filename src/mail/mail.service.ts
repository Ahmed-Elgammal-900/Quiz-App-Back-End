import { Injectable } from '@nestjs/common';
import { render } from '@react-email/components';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';
import PasswordResetEmail from './templates/reset-password';

@Injectable()
export class MailService {
  private resend: Resend;
  constructor(private configService: ConfigService) {
    this.resend = new Resend(configService.get('RESEND_API_KEY'));
  }

  async sendResetPasswordEmail(email: string, resetToken: string) {
    const appUrl = this.configService.get<string>('ORIGIN');
    const resetUrl = `${appUrl}/reset-password?token=${resetToken}`;

    const emailHtml = await render(PasswordResetEmail({ resetUrl }));

    const { data, error } = await this.resend.emails.send({
      from: 'test',
      to: email,
      subject: 'Reset Password',
      html: emailHtml,
    });

    if (error) {
      throw new Error(`Failed to send mail: ${error}`);
    }

    return data;
  }
}
