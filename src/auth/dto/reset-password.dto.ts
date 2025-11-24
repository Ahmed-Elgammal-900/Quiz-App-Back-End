import { IsNotEmpty, IsString } from 'class-validator';
import { UpdateAuthDto } from './update-auth.dto';
import { OmitType } from '@nestjs/mapped-types';
import { CreateAuthDto } from './create-auth.dto';

export class ResetPasswordDto extends OmitType(CreateAuthDto, [
  'email',
  'name',
] as const) {
  @IsNotEmpty()
  @IsString()
  resetToken: string;
}
