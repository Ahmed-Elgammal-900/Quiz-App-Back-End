import { OmitType } from '@nestjs/swagger';
import { VerifyOtpDto } from './otp.dto';

export class ResendOtpDto extends OmitType(VerifyOtpDto, ['otp'] as const) {}
