import { OmitType } from '@nestjs/mapped-types';
import { VerifyOtpDto } from './otp.dto';

export class ResendOtpDto extends OmitType(VerifyOtpDto, ['otp'] as const) {}
