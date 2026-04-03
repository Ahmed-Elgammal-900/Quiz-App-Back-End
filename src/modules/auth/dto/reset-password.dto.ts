import { IsNotEmpty, IsString } from 'class-validator';
import { OmitType } from '@nestjs/swagger';
import { ApiProperty } from '@nestjs/swagger';
import { CreateAuthDto } from './signup.dto';

export class ResetPasswordDto extends OmitType(CreateAuthDto, [
  'email',
  'name',
] as const) {
  @ApiProperty({
    description: 'Password reset token received via email',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @IsNotEmpty()
  @IsString()
  resetToken!: string;
}
