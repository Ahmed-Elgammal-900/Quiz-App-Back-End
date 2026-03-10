import { IsString, IsNotEmpty, Length } from "class-validator";

export class VerifyOtpDto {
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  otp: string;
}
