import { IsString, IsNotEmpty, Length, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyOtpDto {
  @ApiProperty({
    description: 'User UUID',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @IsString()
  @IsNotEmpty()
  @IsUUID()
  id!: string;

  @ApiProperty({
    description: 'The 6-digit OTP sent to the user email',
    example: '482910',
    minLength: 6,
    maxLength: 6,
  })
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  otp!: string;
}
