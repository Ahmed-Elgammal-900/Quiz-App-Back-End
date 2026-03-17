import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { MailService } from './mail.service';
import * as nodemailer from 'nodemailer';
import { render } from '@react-email/components';

// ── Mocks ──────────────────────────────────────────────────────────────────

jest.mock('nodemailer');
jest.mock('@react-email/components', () => ({ render: jest.fn() }));
jest.mock('./templates/reset-password', () => ({
  __esModule: true,
  default: jest.fn((props) => props), // returns props so render() receives something
}));
jest.mock('./templates/email-verification', () => ({
  __esModule: true,
  default: jest.fn((props) => props),
}));

const mockSendMail = jest.fn();
const mockCreateTransport = nodemailer.createTransport as jest.Mock;

// ── Helpers ────────────────────────────────────────────────────────────────

const VALID_CONFIG: Record<string, string> = {
  GMAIL_USER: 'test@gmail.com',
  GMAIL_APP_PASSWORD: 'app-password',
  FRONT_END_ORIGIN: 'https://quizzer.app',
};

function buildConfigService(overrides: Partial<Record<string, string>> = {}) {
  const config = { ...VALID_CONFIG, ...overrides };
  return {
    get: jest.fn((key: string) => config[key] ?? undefined),
  };
}

async function buildService(configService: ReturnType<typeof buildConfigService>) {
  mockCreateTransport.mockReturnValue({ sendMail: mockSendMail });

  const module: TestingModule = await Test.createTestingModule({
    providers: [
      MailService,
      { provide: ConfigService, useValue: configService },
    ],
  }).compile();

  return module.get<MailService>(MailService);
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('MailService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (render as jest.Mock).mockResolvedValue('<html>email</html>');
  });

  // ── Constructor ────────────────────────────────────────────────────────

  describe('constructor', () => {
    it('should initialise and create a nodemailer transporter with valid config', async () => {
      await buildService(buildConfigService());

      expect(mockCreateTransport).toHaveBeenCalledWith({
        service: 'gmail',
        auth: { user: 'test@gmail.com', pass: 'app-password' },
      });
    });

    it.each([
      ['GMAIL_USER', { GMAIL_USER: undefined }],
      ['GMAIL_APP_PASSWORD', { GMAIL_APP_PASSWORD: undefined }],
      ['FRONT_END_ORIGIN', { FRONT_END_ORIGIN: undefined }],
    ])('should throw when %s is missing', async (_, overrides) => {
      mockCreateTransport.mockReturnValue({ sendMail: mockSendMail });

      const module = Test.createTestingModule({
        providers: [
          MailService,
          { provide: ConfigService, useValue: buildConfigService(overrides as any) },
        ],
      });

      await expect(module.compile()).rejects.toThrow('Mail configuration is incomplete');
    });

    it('should throw when FRONT_END_ORIGIN is not a valid URL', async () => {
      mockCreateTransport.mockReturnValue({ sendMail: mockSendMail });

      const module = Test.createTestingModule({
        providers: [
          MailService,
          {
            provide: ConfigService,
            useValue: buildConfigService({ FRONT_END_ORIGIN: 'not-a-url' }),
          },
        ],
      });

      await expect(module.compile()).rejects.toThrow(
        'FRONT_END_ORIGIN must be a valid absolute URL',
      );
    });
  });

  // ── sendResetPasswordEmail ─────────────────────────────────────────────

  describe('sendResetPasswordEmail', () => {
    let service: MailService;

    beforeEach(async () => {
      service = await buildService(buildConfigService());
    });

    it('should send a reset-password email with a correctly formed reset URL', async () => {
      mockSendMail.mockResolvedValue({ messageId: 'abc123' });

      await service.sendResetPasswordEmail('user@example.com', 'tok_abc', 'Alice');

      expect(render).toHaveBeenCalledWith(
        expect.objectContaining({
          resetUrl: 'https://quizzer.app/reset-password?token=tok_abc',
          recipientName: 'Alice',
        }),
      );
    });

    it('should call sendMail with the correct envelope', async () => {
      mockSendMail.mockResolvedValue({ messageId: 'abc123' });

      await service.sendResetPasswordEmail('user@example.com', 'tok_abc');

      expect(mockSendMail).toHaveBeenCalledWith({
        from: '"Quizzer" <test@gmail.com>',
        to: 'user@example.com',
        subject: 'Quizzer - Reset Password',
        html: '<html>email</html>',
      });
    });

    it('should return the result from sendMail', async () => {
      const mockResult = { messageId: 'abc123', accepted: ['user@example.com'] };
      mockSendMail.mockResolvedValue(mockResult);

      const result = await service.sendResetPasswordEmail('user@example.com', 'tok_abc');

      expect(result).toEqual(mockResult);
    });

    it('should work without an optional name', async () => {
      mockSendMail.mockResolvedValue({});

      await service.sendResetPasswordEmail('user@example.com', 'tok_abc');

      expect(render).toHaveBeenCalledWith(
        expect.objectContaining({ recipientName: undefined }),
      );
    });

    it('should throw a wrapped error when sendMail rejects with an Error', async () => {
      mockSendMail.mockRejectedValue(new Error('SMTP connection refused'));

      await expect(
        service.sendResetPasswordEmail('user@example.com', 'tok_abc'),
      ).rejects.toThrow('Failed to send mail: SMTP connection refused');
    });

    it('should throw a wrapped error when sendMail rejects with a non-Error value', async () => {
      mockSendMail.mockRejectedValue('raw string error');

      await expect(
        service.sendResetPasswordEmail('user@example.com', 'tok_abc'),
      ).rejects.toThrow('Failed to send mail: raw string error');
    });
  });

  // ── sendOtpEmail ───────────────────────────────────────────────────────

  describe('sendOtpEmail', () => {
    let service: MailService;

    beforeEach(async () => {
      service = await buildService(buildConfigService());
    });

    it('should render the OTP template with correct props', async () => {
      mockSendMail.mockResolvedValue({});

      await service.sendOtpEmail('user@example.com', '123456', 'Bob', 10);

      expect(render).toHaveBeenCalledWith(
        expect.objectContaining({
          otp: '123456',
          recipientName: 'Bob',
          expiryMins: 10,
        }),
      );
    });

    it('should default expiryMins to 5 when not provided', async () => {
      mockSendMail.mockResolvedValue({});

      await service.sendOtpEmail('user@example.com', '123456');

      expect(render).toHaveBeenCalledWith(
        expect.objectContaining({ expiryMins: 5 }),
      );
    });

    it('should call sendMail with the correct envelope', async () => {
      mockSendMail.mockResolvedValue({});

      await service.sendOtpEmail('user@example.com', '999999', 'Bob');

      expect(mockSendMail).toHaveBeenCalledWith({
        from: '"Quizzer" <test@gmail.com>',
        to: 'user@example.com',
        subject: 'Quizzer - Email Verification OTP',
        html: '<html>email</html>',
      });
    });

    it('should return the result from sendMail', async () => {
      const mockResult = { messageId: 'otp-msg-id' };
      mockSendMail.mockResolvedValue(mockResult);

      const result = await service.sendOtpEmail('user@example.com', '000000');

      expect(result).toEqual(mockResult);
    });

    it('should work without an optional name', async () => {
      mockSendMail.mockResolvedValue({});

      await service.sendOtpEmail('user@example.com', '123456');

      expect(render).toHaveBeenCalledWith(
        expect.objectContaining({ recipientName: undefined }),
      );
    });

    it('should throw a wrapped error when sendMail rejects with an Error', async () => {
      mockSendMail.mockRejectedValue(new Error('Timeout'));

      await expect(
        service.sendOtpEmail('user@example.com', '123456'),
      ).rejects.toThrow('Failed to send mail: Timeout');
    });

    it('should throw a wrapped error when sendMail rejects with a non-Error value', async () => {
      mockSendMail.mockRejectedValue(42);

      await expect(
        service.sendOtpEmail('user@example.com', '123456'),
      ).rejects.toThrow('Failed to send mail: 42');
    });
  });
});