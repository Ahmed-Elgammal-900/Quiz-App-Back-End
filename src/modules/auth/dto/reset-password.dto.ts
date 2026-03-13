import { IsNotEmpty, IsString } from 'class-validator';
import { OmitType } from '@nestjs/mapped-types';
import { CreateAuthDto } from './signup.dto';

export class ResetPasswordDto extends OmitType(CreateAuthDto, [
  'email',
  'name',
] as const) {
  @IsNotEmpty()
  @IsString()
  resetToken: string;
}
