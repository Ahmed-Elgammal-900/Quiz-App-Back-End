import { IsString, IsNotEmpty, Length, IsUUID } from 'class-validator';

export class VerifyOtpDto {
  @IsString()
  @IsNotEmpty()
  @IsUUID()
  id: string;

  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  otp: string;
}
